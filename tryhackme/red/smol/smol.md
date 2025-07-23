
# Smol

This room is a red challenge in which the description tells us directly that this is a **WordPress** website which has a publicly known vulnerable plugin, highlighting the risks of neglecting software updates and security patches. 

## Recon

We start by doing a normal port scan with Nmap and find 2 open ports. I leave the all port scan running into the background so I can see if there's any ports that aren't visible in the top 1000, but we find nothing but the SSH on port 22 and the HTTP on port 80.

![Nmap Scan Result](./screenshots/recon1.png)

I try to see how the website is looking, but when I try to access it it tells me we can't connect to the server at www.smol.thm, so I go and add it at /etc/hosts.

![Can't connect to the server](./screenshots/recon2.png)

I start navigating the main page and meanwhile, I will put a directory scan to search if we can find anything that we don't see on the main page.

![Main page](./screenshots/recon3.png)

If we scroll all the way down, the hint at the beggining of the challenge of it being WordPress is being confirmed.

![WordPress](./screenshots/recon4.png)

