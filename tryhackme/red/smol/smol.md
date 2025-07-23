
# Smol

This room is a red challenge in which the description tells us directly that this is a **WordPress** website which has a publicly known vulnerable plugin, highlighting the risks of neglecting software updates and security patches. 

---

## Recon

We start by doing a normal port scan with Nmap and find 2 open ports. I leave the all port scan running into the background so I can see if there's any ports that aren't visible in the top 1000, but we find nothing but the SSH on port 22 and the HTTP on port 80.

![Nmap Scan Result](./screenshots/recon1.png)