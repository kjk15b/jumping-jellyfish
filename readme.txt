extract_iocs


Overview:
    * User supplies a URL (example: https://google.com)
    * BeautifulSoup filters and cleans HTML to pass to iocextract (as a str)
    * Aggregate emails, ipv4, urls, sha1, sha256, sha512 and md5 Hashes
    * content is written to disk as a UUID with a timestamp text file


Libraries:
    * iocextract
    * bs4


Example URLs to try:
    * https://blogs.blackberry.com/en/2022/11/romcom-spoofing-solarwinds-keepass