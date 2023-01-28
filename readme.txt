extract_iocs


Overview:
    * User supplies a URL (example: https://google.com)
    * BeautifulSoup filters and cleans HTML to pass to iocextract (as a str)
    * Aggregate emails, ipv4, urls, sha1, sha256, sha512 and md5 Hashes
    * content is written to disk as a UUID with a timestamp text file


Known Limitations:
    * Will really only work on OSINT feeds 
    * Has trouble working with encoded PDFs, so just try to hit HTML

Libraries:
    * iocextract
    * bs4


Example URLs to try:
    * https://blogs.blackberry.com/en/2022/11/romcom-spoofing-solarwinds-keepass
    * https://blogs.blackberry.com/en/2023/01/emotet-returns-with-new-methods-of-evasion
    * https://unit42.paloaltonetworks.com/emotet-malware-summary-epoch-4-5/
    * https://www.cisa.gov/uscert/ncas/alerts/aa21-048a
    * https://www.cybereason.com/blog/research/back-to-the-future-inside-the-kimsuky-kgh-spyware-suite
