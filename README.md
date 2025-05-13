# Liceo - HackMyVM (Easy)

![Liceo.png](Liceo.png)

## Übersicht

*   **VM:** Liceo
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Liceo)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2024-04-30
*   **Original-Writeup:** https://alientec1908.github.io/Liceo_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Liceo" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer unsicheren Dateiupload-Funktion auf dem Webserver. Es war möglich, eine PHP-Webshell mit der Endung `.phtml` hochzuladen, da der Filter nur `.php`-Dateien blockierte. Dies ermöglichte Remote Code Execution (RCE) als Benutzer `www-data`. Die finale Rechteausweitung zu Root gelang durch die Ausnutzung einer gefährlichen SUID-Fehlkonfiguration auf der Bash-Executable (`/usr/bin/bash`), die es erlaubte, eine Shell mit Root-Rechten zu starten.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `dirb`
*   `nikto`
*   `nmap`
*   `ftp`
*   `gobuster`
*   `nc` (netcat)
*   `python3 http.server`
*   `wget`
*   `find`
*   `getcap`
*   `uname`
*   `msfconsole` (Metasploit)
*   Standard Linux-Befehle (`cat`, `ls`, `cd`, `id`, `grep`, `rm`, `mkfifo`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Liceo" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Port Scanning:**
    *   IP-Adresse des Ziels (192.168.2.113) mit `arp-scan` identifiziert.
    *   `/etc/hosts`-Eintrag für `liceo.hmv` hinzugefügt.
    *   `nmap`-Scan offenbarte offene Ports: FTP (21/tcp, vsftpd 3.0.5, anonymer Login erlaubt), SSH (22/tcp, OpenSSH 8.9p1) und HTTP (80/tcp, Apache 2.4.52).
    *   `nikto` und `dirb` lieferten weitere Details zum Webserver, u.a. das Verzeichnis `/uploads/`.

2.  **FTP Enumeration:**
    *   Anonymer FTP-Login war erfolgreich.
    *   Die Datei `note.txt` wurde heruntergeladen. Sie enthielt potenzielle Benutzernamen (`pedro`, `matias`, `maria`, `adrian`) und eine E-Mail-Adresse.
    *   Schreibrechte für den anonymen FTP-Benutzer waren nicht vorhanden.

3.  **Web Application Attack (File Upload & Initial Access als `www-data`):**
    *   Ein `gobuster`-Scan auf `http://liceo.hmv/` fand die Datei `upload.php`.
    *   Die Upload-Funktion blockierte `.php`-Dateien (Blacklist).
    *   Es war jedoch möglich, eine PHP-Webshell (z.B. ``) mit der Endung `.phtml` hochzuladen, da Apache diese als PHP interpretierte.
    *   Die hochgeladene Datei war unter `http://liceo.hmv/uploads/shell.phtml` erreichbar.
    *   Durch Aufrufen der URL mit einem `cmd`-Parameter (z.B. `?cmd=id`) konnte Remote Code Execution (RCE) als `www-data` erreicht werden.
    *   Eine Reverse Shell wurde zum Angreifer-System (lauschender Netcat-Listener) als `www-data` aufgebaut.

4.  **Post-Exploitation Enumeration (als `www-data`):**
    *   Im Web-Root-Verzeichnis (`/var/www/html/`) wurde eine Datei `liceoweb.zip` gefunden und heruntergeladen. (Inhalt im Bericht nicht weiter analysiert)
    *   Im Verzeichnis `/home/` wurde der Benutzer `dev` identifiziert. `www-data` hatte Lesezugriff auf `/home/dev/`.
    *   Die User-Flag (`71ab613fa286844425523780a7ebbab2`) wurde in `/home/dev/user.txt` gefunden.
    *   Die Suche nach SUID-Dateien (`find / -type f -perm -4000 -ls`) offenbarte, dass `/usr/bin/bash` SUID-Root-Berechtigungen hatte (`-rwsr-sr-x`).

5.  **Privilege Escalation (von `www-data` zu `root` via SUID Bash):**
    *   Versuche, über Metasploit mit Kernel-Exploits (Pwnkit, DirtyPipe) Root-Rechte zu erlangen, scheiterten.
    *   Die SUID-Fehlkonfiguration von Bash wurde ausgenutzt.
    *   Durch Ausführen von `/bin/bash -p` in der `www-data`-Shell wurde eine neue Bash-Sitzung gestartet, die aufgrund des SUID-Bits die effektiven Root-Rechte (`euid=0(root)`) beibehielt.
    *   Die Root-Flag (`BF9A57023EDD8CFAB92B8EA516676B0D`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Unsicherer Dateiupload (Blacklist Bypass):** Die Webanwendung verwendete eine unzureichende Blacklist, um PHP-Uploads zu verhindern. Durch die Verwendung der alternativen Dateiendung `.phtml` (die von Apache als PHP interpretiert wurde) konnte eine Webshell hochgeladen werden, was zu RCE führte.
*   **SUID-Fehlkonfiguration (Bash):** Die Bash-Executable (`/usr/bin/bash`) hatte das SUID-Bit gesetzt und gehörte `root`. Dies ist eine extrem gefährliche Fehlkonfiguration, die eine einfache Privilege Escalation zu Root ermöglicht, indem `bash -p` ausgeführt wird.
*   **Anonymer FTP-Zugriff mit Informationspreisgabe:** Anonymer FTP-Zugriff war erlaubt und enthielt eine Notiz mit potenziellen Benutzernamen.
*   **Directory Indexing:** Mehrere Verzeichnisse auf dem Webserver erlaubten das Auflisten von Dateien.

## Flags

*   **User Flag (`/home/dev/user.txt`):** `71ab613fa286844425523780a7ebbab2`
*   **Root Flag (`/root/root.txt`):** `BF9A57023EDD8CFAB92B8EA516676B0D`

## Tags

`HackMyVM`, `Liceo`, `Easy`, `File Upload Vulnerability`, `phtml Webshell`, `SUID Exploit`, `SUID Bash`, `Anonymous FTP`, `Linux`, `Web`, `Privilege Escalation`, `Apache`
