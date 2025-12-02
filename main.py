#!/usr/bin/env python3
"""
ADVANCED CREDENTIAL EXTRACTOR v5.0 ULTIMATE
- Multi-mode extraction (All / Targeted / By Category)
- Smart URL detection (Web + Android/iOS + Desktop apps)
- Advanced pattern matching for 100+ sites
- Multiple file format support (TXT, JSON, CSV, XML, SQLite)
- Password strength analysis
- Duplicate/reuse detection
- Category-based filtering
- Multi-language credential field detection
"""

import os
import re
import zipfile
import sys
import json
import csv
import sqlite3
import tempfile
import subprocess
import shutil
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Thread-safe list for collecting results
_cards_lock = threading.Lock()

def extract_rar_to_temp(rar_path, password=None):
    """Extract RAR file to a temporary directory using 7z."""
    temp_dir = tempfile.mkdtemp(prefix='rar_extract_')
    try:
        cmd = ['7z', 'x', '-y', f'-o{temp_dir}']
        if password:
            cmd.append(f'-p{password}')
        cmd.append(rar_path)
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            if 'Wrong password' in result.stderr or 'password' in result.stderr.lower():
                return None, 'password_needed'
            return None, f'extraction_error: {result.stderr[:200]}'
        
        return temp_dir, None
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, 'timeout'
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, str(e)

# Binary/skip file extensions - skip these for CC extraction
SKIP_EXTENSIONS = frozenset([
    '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.db', '.sqlite', '.sqlite3',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp', '.svg', '.tiff',
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flac', '.ogg', '.wmv',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    '.pyc', '.pyo', '.class', '.o', '.obj',
    '.iso', '.img', '.dmg', '.apk', '.ipa',
])

# Text file extensions - prioritize these
TEXT_EXTENSIONS = frozenset([
    '.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', '.md',
    '.ini', '.cfg', '.conf', '.config', '.yml', '.yaml', '.env',
])

def is_likely_text_file(filename, file_size=0):
    """Fast check if file is likely to contain text with credit cards."""
    name_lower = filename.lower()
    ext = os.path.splitext(name_lower)[1]
    
    # Skip known binary extensions
    if ext in SKIP_EXTENSIONS:
        return False
    
    # Skip very large files (>10MB)
    if file_size > 10 * 1024 * 1024:
        return False
    
    # Skip very small files (<10 bytes)
    if file_size > 0 and file_size < 10:
        return False
    
    # Prioritize known text extensions
    if ext in TEXT_EXTENSIONS:
        return True
    
    # Check for credit card related keywords in filename
    cc_keywords = ['card', 'credit', 'cc', 'payment', 'bank', 'password', 'login', 'cred', 'autofill']
    if any(kw in name_lower for kw in cc_keywords):
        return True
    
    # Default: try it if extension is unknown
    return ext == '' or len(ext) <= 5

def is_binary_content(data):
    """Quick check if data looks like binary content."""
    if len(data) < 100:
        return False
    # Check first 1000 bytes for null bytes or high ratio of non-printable chars
    sample = data[:1000]
    if b'\x00' in sample:
        return True
    non_printable = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))
    return non_printable > len(sample) * 0.3

EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', re.I)
PHONE_RE = re.compile(r'^\+?\d{8,15}$')
USERNAME_RE = re.compile(r'^[a-zA-Z0-9._-]{3,50}$')
HEX_ID_RE = re.compile(r'^[a-fA-F0-9]{20,}$')

# Discord Token Pattern
DISCORD_TOKEN_RE = re.compile(r'([MN][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6,7}\.[A-Za-z\d_-]{27}|mfa\.[A-Za-z\d_-]{84})', re.IGNORECASE)

# Credit Card Patterns
CC_NUMBER_RE = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b')
CC_NUMBER_SPACED_RE = re.compile(r'\b(?:4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}|3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5})\b')

# CC Labels for labeled format
CC_NUMBER_LABELS = ['cardnumber', 'card_number', 'card number', 'cc', 'ccnum', 'cc_num', 'creditcard', 
                    'credit_card', 'credit card', 'pan', 'card', 'numero', 'card#', 'cardno', 'card_no',
                    'debit', 'debitcard', 'debit_card', 'numero de tarjeta', 'numero tarjeta', 'tarjeta']
CC_CVV_LABELS = ['cvc', 'cvv', 'cvc2', 'cvv2', 'cv2', 'security_code', 'security code', 'securitycode',
                 'card_code', 'cardcode', 'codigo', 'codigo de seguridad', 'verification', 'cid', 'csc']
CC_EXP_LABELS = ['exp', 'expiry', 'expiration', 'expirationdate', 'expiration_date', 'expiration date',
                 'exp_date', 'expdate', 'valid', 'validthru', 'valid_thru', 'valid thru', 'expires',
                 'fecha', 'vencimiento', 'fecha de vencimiento', 'mm/yy', 'mm/yyyy', 'month', 'year']
CC_NAME_LABELS = ['nameoncard', 'name_on_card', 'name on card', 'cardholder', 'card_holder', 'card holder',
                  'holder', 'holdername', 'holder_name', 'nombre', 'titular', 'nombre del titular']

# Card type patterns for identification
CARD_TYPES = {
    'visa': re.compile(r'^4[0-9]{12}(?:[0-9]{3})?$'),
    'mastercard': re.compile(r'^5[1-5][0-9]{14}$|^2(?:2(?:2[1-9]|[3-9][0-9])|[3-6][0-9]{2}|7(?:[01][0-9]|20))[0-9]{12}$'),
    'amex': re.compile(r'^3[47][0-9]{13}$'),
    'discover': re.compile(r'^6(?:011|5[0-9]{2})[0-9]{12}$'),
    'diners': re.compile(r'^3(?:0[0-5]|[68][0-9])[0-9]{11}$'),
    'jcb': re.compile(r'^(?:2131|1800|35\d{3})\d{11}$'),
    'unionpay': re.compile(r'^62[0-9]{14,17}$'),
    'maestro': re.compile(r'^(?:5[0678]\d\d|6304|6390|67\d\d)\d{8,15}$'),
}

USER_LABELS_MULTI = [
    'username', 'user', 'login', 'email', 'mail', 'account', 'usuario', 'user name', 
    'e-mail', 'usr', 'utilisateur', 'benutzer', 'utente', 'nome', 'correo', 
    'cuenta', 'konto', 'compte', 'id', 'userid', 'user_id', 'member', 'nickname',
    'handle', 'profile', 'identity', 'credential', 'login_email', 'login_user'
]

PASS_LABELS_MULTI = [
    'password', 'pass', 'pwd', 'passwd', 'senha', 'contraseña', 'secret', 
    'mot de passe', 'pw', 'passwort', 'parola', 'haslo', 'wachtwoord',
    'clave', 'chiave', 'motdepasse', 'passw', 'pswd', 'key', 'pin',
    'login_password', 'user_password', 'auth_password'
]

URL_LABELS = [
    'url', 'host', 'site', 'website', 'link', 'domain', 'origin', 
    'address', 'location', 'source', 'target', 'uri', 'href'
]

GIT_PATTERNS = [
    r'^git@.*\.git', r'github\.com.*\.git', r'gitlab\.com.*\.git', 
    r'bitbucket\.org.*\.git', r'\.git[,"\']',
]

GARBAGE_USERNAMES = frozenset([
    'password', 'username', 'value', 'null', 'none', 'n/a', 'empty', 'url',
    'application', 'email', 'user', 'pass', 'true', 'false', 'undefined',
    'test', 'default', 'example', 'sample', 'demo', 'name', 'type', 'status',
    'homepage', 'repository', 'description', 'version', 'license', 'author',
    'private', 'public', 'dependencies', 'devdependencies', 'scripts', 'main',
    'browser', 'module', 'files', 'keywords', 'bugs', 'engines', 'os', 'cpu',
    'pid', 'hwid', 'guid', 'uuid', 'processid', 'machineid', 'deviceid',
    'system', 'host', 'hostname', 'domain', 'workgroup', 'computer',
    'traffic', 'processor', 'integrity', 'userlanguage', 'title', 'card',
    'resolution', 'timezone', 'ram', 'commandline', 'command', 'cmd',
    'path', 'file', 'folder', 'directory', 'size', 'date', 'time', 'hash',
    'language', 'compatible', 'servername', 'machine', 'process', 'unknown',
    'anonymous', 'guest', 'admin', 'administrator', 'root', 'service'
])

GARBAGE_NUMBERS = frozenset([
    '2147483647', '4294967295', '4294967296', '536870912', '1073741824',
    '2147483648', '268435456', '134217728', '67108864', '0', '1', '2',
    '1000000000', '999999999', '123456789', '987654321'
])

GARBAGE_PASSWORDS = frozenset([
    'password', 'username', 'value', 'null', 'none', 'n/a', 'empty', 'url',
    'application', 'email', 'user', 'pass', 'true', 'false', 'undefined',
    'homepage', 'repository', 'description', 'french', 'english', 'spanish',
    'german', 'italian', 'portuguese', 'russian', 'chinese', 'japanese',
    'high', 'medium', 'low', 'normal', 'unknown', 'system', 'admin'
])

SITE_CATEGORIES = {
    'streaming': ['netflix', 'spotify', 'disney', 'hulu', 'amazon', 'hbo', 'crunchyroll', 
                  'funimation', 'paramount', 'peacock', 'appletv', 'dazn', 'mubi', 'tidal',
                  'deezer', 'pandora', 'soundcloud', 'youtube', 'twitch', 'vimeo'],
    'gaming': ['steam', 'epic', 'origin', 'ubisoft', 'playstation', 'xbox', 'nintendo',
               'roblox', 'minecraft', 'fortnite', 'valorant', 'league', 'riot', 'blizzard',
               'battlenet', 'gog', 'humble', 'itch', 'rockstar', 'bethesda', 'activision'],
    'social': ['instagram', 'facebook', 'twitter', 'tiktok', 'snapchat', 'linkedin',
               'pinterest', 'reddit', 'tumblr', 'telegram', 'whatsapp', 'wechat', 'line',
               'viber', 'signal', 'discord', 'slack', 'skype', 'zoom', 'teams'],
    'finance': ['paypal', 'coinbase', 'binance', 'crypto', 'kraken', 'gemini', 'robinhood',
                'cashapp', 'venmo', 'zelle', 'wise', 'revolut', 'chime', 'sofi', 'webull',
                'etrade', 'fidelity', 'schwab', 'chase', 'bankofamerica', 'wellsfargo', 'citi'],
    'shopping': ['amazon', 'ebay', 'aliexpress', 'wish', 'etsy', 'walmart', 'target',
                 'bestbuy', 'newegg', 'wayfair', 'ikea', 'costco', 'samsclub', 'homedepot',
                 'lowes', 'macys', 'nordstrom', 'zappos', 'nike', 'adidas', 'mercadolibre'],
    'email': ['gmail', 'google', 'outlook', 'yahoo', 'icloud', 'protonmail', 'zoho',
              'aol', 'mail', 'yandex', 'gmx', 'tutanota', 'fastmail', 'mailfence'],
    'cloud': ['dropbox', 'onedrive', 'gdrive', 'box', 'mega', 'pcloud', 'sync', 'icloud',
              'mediafire', 'wetransfer', 'sendspace', 'zippyshare'],
    'vpn': ['nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'pia', 'protonvpn',
            'mullvad', 'windscribe', 'tunnelbear', 'hotspotshield', 'ipvanish'],
    'education': ['coursera', 'udemy', 'skillshare', 'linkedin learning', 'masterclass',
                  'duolingo', 'babbel', 'rosettastone', 'khan', 'edx', 'codecademy'],
    'work': ['github', 'gitlab', 'bitbucket', 'jira', 'confluence', 'notion', 'trello',
             'asana', 'monday', 'airtable', 'figma', 'canva', 'adobe', 'office365'],
    'dating': ['tinder', 'bumble', 'hinge', 'match', 'okcupid', 'pof', 'badoo', 'grindr'],
    'food': ['doordash', 'ubereats', 'grubhub', 'postmates', 'instacart', 'seamless',
             'deliveroo', 'justeat', 'rappi', 'ifood', 'swiggy', 'zomato'],
    'travel': ['airbnb', 'booking', 'expedia', 'hotels', 'kayak', 'tripadvisor', 'vrbo',
               'priceline', 'hotwire', 'trivago', 'agoda', 'hostelworld'],
    'adult': ['pornhub', 'onlyfans', 'chaturbate', 'xvideos', 'xnxx', 'xhamster', 'redtube']
}

POPULAR_SITES = {
    'netflix': {
        'domains': ['netflix.com', 'netflix'],
        'android': ['com.netflix.mediaclient', 'com.netflix'],
        'ios': ['com.netflix.Netflix'],
        'desktop': ['Netflix'],
        'keywords': ['netflix'],
        'category': 'streaming'
    },
    'spotify': {
        'domains': ['spotify.com', 'spotify', 'open.spotify.com'],
        'android': ['com.spotify.music', 'com.spotify', 'com.spotify.lite'],
        'ios': ['com.spotify.client'],
        'desktop': ['Spotify'],
        'keywords': ['spotify'],
        'category': 'streaming'
    },
    'disney': {
        'domains': ['disneyplus.com', 'disney+', 'disney.com', 'starplus.com', 'hotstar.com', 'star+'],
        'android': ['com.disney.disneyplus', 'com.disney.starplus', 'com.bamtechmedia.dominguez', 'in.startv.hotstar'],
        'ios': ['com.disney.disneyplus'],
        'desktop': ['Disney+', 'DisneyPlus'],
        'keywords': ['disney', 'disneyplus', 'disney+', 'starplus', 'star+', 'hotstar'],
        'category': 'streaming'
    },
    'hulu': {
        'domains': ['hulu.com', 'hulu'],
        'android': ['com.hulu.plus', 'com.hulu', 'com.hulu.livingroomplus'],
        'ios': ['com.hulu.plus'],
        'keywords': ['hulu'],
        'category': 'streaming'
    },
    'amazon': {
        'domains': ['amazon.com', 'amazon.co', 'primevideo.com', 'amazon.de', 'amazon.es', 'amazon.fr', 
                    'amazon.it', 'amazon.in', 'amazon.co.uk', 'amazon.ca', 'amazon.com.mx', 'amazon.com.br',
                    'amazon.co.jp', 'amazon.com.au', 'aws.amazon.com'],
        'android': ['com.amazon.avod.thirdpartyclient', 'com.amazon.mShop.android.shopping', 'com.amazon',
                    'com.amazon.kindle', 'com.amazon.mp3', 'com.amazon.storm.lightning.client.aosp'],
        'ios': ['com.amazon.Amazon', 'com.amazon.aiv.AIVApp'],
        'desktop': ['Amazon', 'Prime Video'],
        'keywords': ['amazon', 'primevideo', 'prime video', 'prime', 'aws', 'kindle'],
        'categories': ['shopping', 'streaming']
    },
    'primevideo': {
        'domains': ['primevideo.com', 'amazon.com/gp/video'],
        'android': ['com.amazon.avod.thirdpartyclient', 'com.amazon.avod'],
        'ios': ['com.amazon.aiv.AIVApp'],
        'keywords': ['primevideo', 'prime video'],
        'category': 'streaming'
    },
    'hbo': {
        'domains': ['hbomax.com', 'hbo.com', 'max.com', 'play.hbomax.com'],
        'android': ['com.hbo.hbonow', 'com.hbo.max', 'com.wbd.stream', 'com.hbo.android.app'],
        'ios': ['com.hbo.hbonow', 'com.hbo.HBOMax'],
        'keywords': ['hbo', 'hbomax', 'hbo max', 'max'],
        'category': 'streaming'
    },
    'crunchyroll': {
        'domains': ['crunchyroll.com', 'crunchyroll', 'beta.crunchyroll.com'],
        'android': ['com.crunchyroll.crunchyroid', 'com.crunchyroll.crunchy_android'],
        'ios': ['com.crunchyroll.iphone'],
        'keywords': ['crunchyroll', 'crunchy'],
        'category': 'streaming'
    },
    'paramount': {
        'domains': ['paramountplus.com', 'paramount+', 'cbs.com'],
        'android': ['com.cbs.app', 'com.paramount.plus'],
        'ios': ['com.cbs.ott'],
        'keywords': ['paramount', 'paramount+', 'cbs'],
        'category': 'streaming'
    },
    'peacock': {
        'domains': ['peacocktv.com', 'peacock'],
        'android': ['com.peacocktv.peacockandroid'],
        'ios': ['com.peacock.peacock'],
        'keywords': ['peacock', 'nbcuniversal'],
        'category': 'streaming'
    },
    'youtube': {
        'domains': ['youtube.com', 'youtu.be', 'youtube', 'music.youtube.com', 'tv.youtube.com'],
        'android': ['com.google.android.youtube', 'com.google.android.apps.youtube.music'],
        'ios': ['com.google.ios.youtube'],
        'keywords': ['youtube', 'yt', 'youtubetv'],
        'category': 'streaming'
    },
    'twitch': {
        'domains': ['twitch.tv', 'twitch.com', 'twitch'],
        'android': ['tv.twitch.android.app', 'tv.twitch'],
        'ios': ['tv.twitch'],
        'keywords': ['twitch'],
        'category': 'streaming'
    },
    'deezer': {
        'domains': ['deezer.com', 'deezer'],
        'android': ['deezer.android.app'],
        'keywords': ['deezer'],
        'category': 'streaming'
    },
    'tidal': {
        'domains': ['tidal.com', 'tidal', 'listen.tidal.com'],
        'android': ['com.aspiro.tidal'],
        'keywords': ['tidal'],
        'category': 'streaming'
    },
    'soundcloud': {
        'domains': ['soundcloud.com', 'soundcloud'],
        'android': ['com.soundcloud.android'],
        'keywords': ['soundcloud'],
        'category': 'streaming'
    },
    'steam': {
        'domains': ['steampowered.com', 'steamcommunity.com', 'store.steampowered.com', 'steam'],
        'android': ['com.valvesoftware.android.steam.community', 'com.valvesoftware'],
        'desktop': ['Steam'],
        'keywords': ['steam', 'steampowered', 'valve'],
        'category': 'gaming'
    },
    'epic': {
        'domains': ['epicgames.com', 'epic games', 'unrealengine.com', 'store.epicgames.com'],
        'android': ['com.epicgames.portal', 'com.epicgames.fortnite'],
        'desktop': ['Epic Games Launcher', 'EpicGamesLauncher'],
        'keywords': ['epic', 'epicgames', 'epic games', 'unreal'],
        'category': 'gaming'
    },
    'origin': {
        'domains': ['origin.com', 'ea.com', 'accounts.ea.com'],
        'android': ['com.ea.origin', 'com.ea'],
        'desktop': ['Origin', 'EA Desktop'],
        'keywords': ['origin', 'ea', 'electronic arts'],
        'category': 'gaming'
    },
    'ubisoft': {
        'domains': ['ubisoft.com', 'uplay', 'ubisoftconnect.com', 'ubi.com'],
        'android': ['com.ubisoft.uplay', 'com.ubisoft'],
        'desktop': ['Ubisoft Connect', 'Uplay'],
        'keywords': ['ubisoft', 'uplay', 'ubi'],
        'category': 'gaming'
    },
    'playstation': {
        'domains': ['playstation.com', 'psn', 'sonyentertainmentnetwork.com', 'store.playstation.com'],
        'android': ['com.scee.psxandroid', 'com.playstation.playstationapp'],
        'ios': ['com.playstation.RemotePlay'],
        'keywords': ['playstation', 'psn', 'ps4', 'ps5', 'sony', 'ps3'],
        'category': 'gaming'
    },
    'xbox': {
        'domains': ['xbox.com', 'xbox live', 'microsoft.com/xbox', 'account.xbox.com'],
        'android': ['com.microsoft.xboxone.smartglass', 'com.microsoft.xbox'],
        'keywords': ['xbox', 'xbox live', 'xbl', 'gamepass'],
        'category': 'gaming'
    },
    'nintendo': {
        'domains': ['nintendo.com', 'accounts.nintendo.com', 'nintendo'],
        'android': ['com.nintendo.znca', 'com.nintendo'],
        'keywords': ['nintendo', 'switch', 'eshop'],
        'category': 'gaming'
    },
    'roblox': {
        'domains': ['roblox.com', 'roblox', 'web.roblox.com'],
        'android': ['com.roblox.client', 'com.roblox'],
        'ios': ['com.roblox.robloxmobile'],
        'keywords': ['roblox', 'robux'],
        'category': 'gaming'
    },
    'minecraft': {
        'domains': ['minecraft.net', 'minecraft', 'mojang.com'],
        'android': ['com.mojang.minecraftpe', 'com.mojang'],
        'ios': ['com.mojang.minecraftpe'],
        'keywords': ['minecraft', 'mojang', 'mc'],
        'category': 'gaming'
    },
    'fortnite': {
        'domains': ['fortnite.com', 'epicgames.com/fortnite', 'fortnite'],
        'android': ['com.epicgames.fortnite'],
        'keywords': ['fortnite', 'fn'],
        'category': 'gaming'
    },
    'valorant': {
        'domains': ['valorant', 'playvalorant.com'],
        'keywords': ['valorant', 'valo'],
        'category': 'gaming'
    },
    'league': {
        'domains': ['leagueoflegends.com', 'lol', 'league of legends', 'lolesports.com'],
        'android': ['com.riotgames.league.wildrift'],
        'keywords': ['league', 'lol', 'leagueoflegends', 'wildrift'],
        'category': 'gaming'
    },
    'riot': {
        'domains': ['riotgames.com', 'authenticate.riotgames.com', 'account.riotgames.com'],
        'android': ['com.riotgames'],
        'keywords': ['riot', 'riotgames'],
        'category': 'gaming'
    },
    'blizzard': {
        'domains': ['blizzard.com', 'battle.net', 'battlenet', 'us.battle.net', 'eu.battle.net'],
        'desktop': ['Battle.net', 'Blizzard'],
        'keywords': ['blizzard', 'battlenet', 'battle.net', 'bnet'],
        'category': 'gaming'
    },
    'rockstar': {
        'domains': ['rockstargames.com', 'socialclub.rockstargames.com'],
        'desktop': ['Rockstar Games Launcher'],
        'keywords': ['rockstar', 'socialclub', 'gta', 'rdr'],
        'category': 'gaming'
    },
    'activision': {
        'domains': ['activision.com', 'callofduty.com', 'profile.callofduty.com'],
        'keywords': ['activision', 'callofduty', 'cod', 'warzone'],
        'category': 'gaming'
    },
    'instagram': {
        'domains': ['instagram.com', 'instagram', 'i.instagram.com'],
        'android': ['com.instagram.android', 'com.instagram', 'com.instagram.lite'],
        'ios': ['com.burbn.instagram'],
        'keywords': ['instagram', 'ig', 'insta'],
        'category': 'social'
    },
    'facebook': {
        'domains': ['facebook.com', 'fb.com', 'm.facebook.com', 'www.facebook.com', 'web.facebook.com'],
        'android': ['com.facebook.katana', 'com.facebook.orca', 'com.facebook', 'com.facebook.lite'],
        'ios': ['com.facebook.Facebook'],
        'keywords': ['facebook', 'fb', 'meta'],
        'category': 'social'
    },
    'twitter': {
        'domains': ['twitter.com', 'x.com', 'mobile.twitter.com', 'api.twitter.com'],
        'android': ['com.twitter.android', 'com.twitter', 'com.twitter.android.lite'],
        'ios': ['com.atebits.Tweetie2'],
        'keywords': ['twitter', 'x.com', 'tweet'],
        'category': 'social'
    },
    'tiktok': {
        'domains': ['tiktok.com', 'tiktok', 'vm.tiktok.com', 'www.tiktok.com'],
        'android': ['com.zhiliaoapp.musically', 'com.ss.android.ugc.trill', 'com.tiktok'],
        'ios': ['com.zhiliaoapp.musically'],
        'keywords': ['tiktok', 'tt', 'musically'],
        'category': 'social'
    },
    'snapchat': {
        'domains': ['snapchat.com', 'snap.com', 'accounts.snapchat.com'],
        'android': ['com.snapchat.android', 'com.snapchat'],
        'ios': ['com.toyopagroup.picaboo'],
        'keywords': ['snapchat', 'snap', 'sc'],
        'category': 'social'
    },
    'linkedin': {
        'domains': ['linkedin.com', 'linkedin', 'www.linkedin.com'],
        'android': ['com.linkedin.android', 'com.linkedin'],
        'ios': ['com.linkedin.LinkedIn'],
        'keywords': ['linkedin', 'li'],
        'category': 'social'
    },
    'pinterest': {
        'domains': ['pinterest.com', 'pinterest', 'pin.it'],
        'android': ['com.pinterest', 'com.pinterest.app'],
        'ios': ['pinterest'],
        'keywords': ['pinterest', 'pin'],
        'category': 'social'
    },
    'reddit': {
        'domains': ['reddit.com', 'reddit', 'old.reddit.com', 'www.reddit.com'],
        'android': ['com.reddit.frontpage'],
        'ios': ['com.reddit.Reddit'],
        'keywords': ['reddit'],
        'category': 'social'
    },
    'discord': {
        'domains': ['discord.com', 'discord.gg', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com'],
        'android': ['com.discord', 'com.discord.app'],
        'ios': ['com.hammerandchisel.discord'],
        'desktop': ['Discord'],
        'keywords': ['discord', 'dc'],
        'category': 'social'
    },
    'telegram': {
        'domains': ['telegram.org', 'web.telegram.org', 't.me'],
        'android': ['org.telegram.messenger', 'org.telegram'],
        'ios': ['ph.telegra.Telegraph'],
        'desktop': ['Telegram'],
        'keywords': ['telegram', 'tg'],
        'category': 'social'
    },
    'whatsapp': {
        'domains': ['whatsapp.com', 'web.whatsapp.com', 'wa.me'],
        'android': ['com.whatsapp', 'com.whatsapp.w4b'],
        'ios': ['net.whatsapp.WhatsApp'],
        'keywords': ['whatsapp', 'wa'],
        'category': 'social'
    },
    'paypal': {
        'domains': ['paypal.com', 'paypal', 'www.paypal.com'],
        'android': ['com.paypal.android.p2pmobile', 'com.paypal'],
        'ios': ['com.yourcompany.PPClient'],
        'keywords': ['paypal', 'pp'],
        'category': 'finance'
    },
    'coinbase': {
        'domains': ['coinbase.com', 'coinbase', 'pro.coinbase.com', 'www.coinbase.com'],
        'android': ['com.coinbase.android', 'com.coinbase'],
        'ios': ['com.coinbase.Coinbase'],
        'keywords': ['coinbase', 'cb'],
        'category': 'finance'
    },
    'binance': {
        'domains': ['binance.com', 'binance', 'binance.us', 'www.binance.com'],
        'android': ['com.binance.dev', 'com.binance'],
        'ios': ['com.binance.trade'],
        'keywords': ['binance', 'bnb'],
        'category': 'finance'
    },
    'kraken': {
        'domains': ['kraken.com', 'kraken', 'www.kraken.com'],
        'android': ['com.kraken.trade'],
        'keywords': ['kraken'],
        'category': 'finance'
    },
    'crypto': {
        'domains': ['crypto.com', 'cryptocurrency'],
        'android': ['co.mona.android', 'com.crypto'],
        'keywords': ['crypto.com', 'cro'],
        'category': 'finance'
    },
    'cashapp': {
        'domains': ['cash.app', 'cashapp', 'square.com'],
        'android': ['com.squareup.cash'],
        'keywords': ['cashapp', 'cash app', 'square'],
        'category': 'finance'
    },
    'venmo': {
        'domains': ['venmo.com', 'venmo'],
        'android': ['com.venmo'],
        'keywords': ['venmo'],
        'category': 'finance'
    },
    'robinhood': {
        'domains': ['robinhood.com', 'robinhood'],
        'android': ['com.robinhood.android'],
        'keywords': ['robinhood', 'rh'],
        'category': 'finance'
    },
    'dropbox': {
        'domains': ['dropbox.com', 'dropbox', 'www.dropbox.com'],
        'android': ['com.dropbox.android', 'com.dropbox'],
        'ios': ['com.getdropbox.Dropbox'],
        'keywords': ['dropbox', 'db'],
        'category': 'cloud'
    },
    'mega': {
        'domains': ['mega.nz', 'mega.io', 'mega'],
        'android': ['mega.privacy.android.app'],
        'keywords': ['mega'],
        'category': 'cloud'
    },
    'gmail': {
        'domains': ['gmail.com', 'accounts.google.com', 'mail.google.com', 'myaccount.google.com'],
        'android': ['com.google.android.gm', 'com.google.android.apps.googlevoice'],
        'ios': ['com.google.Gmail'],
        'keywords': ['gmail', 'google mail', 'googlemail'],
        'category': 'email'
    },
    'google': {
        'domains': ['google.com', 'accounts.google.com', 'myaccount.google.com', 'one.google.com'],
        'android': ['com.google.android.googlequicksearchbox', 'com.google'],
        'ios': ['com.google.GoogleMobile'],
        'keywords': ['google'],
        'category': 'email'
    },
    'outlook': {
        'domains': ['outlook.com', 'hotmail.com', 'outlook', 'hotmail', 'live.com', 'account.live.com', 
                    'login.live.com', 'outlook.live.com', 'login.microsoftonline.com'],
        'android': ['com.microsoft.office.outlook', 'com.microsoft.office'],
        'ios': ['com.microsoft.Office.Outlook'],
        'keywords': ['outlook', 'hotmail', 'live', 'microsoft mail', 'msn'],
        'category': 'email'
    },
    'yahoo': {
        'domains': ['yahoo.com', 'yahoo', 'login.yahoo.com', 'mail.yahoo.com'],
        'android': ['com.yahoo.mobile.client.android.mail', 'com.yahoo'],
        'ios': ['com.yahoo.Aerogram'],
        'keywords': ['yahoo'],
        'category': 'email'
    },
    'protonmail': {
        'domains': ['protonmail.com', 'proton.me', 'mail.proton.me', 'account.proton.me'],
        'android': ['ch.protonmail.android'],
        'keywords': ['protonmail', 'proton'],
        'category': 'email'
    },
    'icloud': {
        'domains': ['icloud.com', 'apple.com', 'appleid.apple.com', 'id.apple.com'],
        'ios': ['com.apple.mobilemail'],
        'keywords': ['icloud', 'apple', 'appleid'],
        'category': 'email'
    },
    'nordvpn': {
        'domains': ['nordvpn.com', 'nordvpn', 'my.nordaccount.com'],
        'android': ['com.nordvpn.android', 'com.nordvpn'],
        'ios': ['com.nordvpn.ios'],
        'keywords': ['nordvpn', 'nord vpn', 'nord'],
        'category': 'vpn'
    },
    'expressvpn': {
        'domains': ['expressvpn.com', 'expressvpn'],
        'android': ['com.expressvpn.vpn', 'com.expressvpn'],
        'keywords': ['expressvpn', 'express vpn', 'evpn'],
        'category': 'vpn'
    },
    'surfshark': {
        'domains': ['surfshark.com', 'surfshark'],
        'android': ['com.surfshark.vpnclient.android'],
        'keywords': ['surfshark'],
        'category': 'vpn'
    },
    'duolingo': {
        'domains': ['duolingo.com', 'duolingo'],
        'android': ['com.duolingo', 'com.duolingo.app'],
        'ios': ['com.duolingo.DuolingoMobile'],
        'keywords': ['duolingo', 'duo'],
        'category': 'education'
    },
    'coursera': {
        'domains': ['coursera.org', 'coursera'],
        'android': ['org.coursera.android'],
        'keywords': ['coursera'],
        'category': 'education'
    },
    'udemy': {
        'domains': ['udemy.com', 'udemy'],
        'android': ['com.udemy.android'],
        'keywords': ['udemy'],
        'category': 'education'
    },
    'github': {
        'domains': ['github.com', 'github', 'api.github.com', 'gist.github.com'],
        'android': ['com.github.android'],
        'desktop': ['GitHub Desktop'],
        'keywords': ['github', 'gh'],
        'category': 'work'
    },
    'gitlab': {
        'domains': ['gitlab.com', 'gitlab'],
        'keywords': ['gitlab'],
        'category': 'work'
    },
    'notion': {
        'domains': ['notion.so', 'notion.com', 'notion'],
        'android': ['notion.id'],
        'keywords': ['notion'],
        'category': 'work'
    },
    'figma': {
        'domains': ['figma.com', 'figma'],
        'keywords': ['figma'],
        'category': 'work'
    },
    'canva': {
        'domains': ['canva.com', 'canva'],
        'android': ['com.canva.editor'],
        'keywords': ['canva'],
        'category': 'work'
    },
    'adobe': {
        'domains': ['adobe.com', 'creativecloud.adobe.com', 'account.adobe.com'],
        'android': ['com.adobe.reader'],
        'desktop': ['Adobe Creative Cloud'],
        'keywords': ['adobe', 'creative cloud', 'photoshop', 'illustrator'],
        'category': 'work'
    },
    'zoom': {
        'domains': ['zoom.us', 'zoom.com', 'zoom'],
        'android': ['us.zoom.videomeetings'],
        'keywords': ['zoom'],
        'category': 'social'
    },
    'ubereats': {
        'domains': ['ubereats.com', 'uber.com'],
        'android': ['com.ubercab.eats', 'com.ubercab'],
        'keywords': ['ubereats', 'uber eats', 'uber'],
        'category': 'food'
    },
    'doordash': {
        'domains': ['doordash.com', 'doordash'],
        'android': ['com.dd.doordash'],
        'keywords': ['doordash'],
        'category': 'food'
    },
    'grubhub': {
        'domains': ['grubhub.com', 'grubhub'],
        'android': ['com.grubhub.android'],
        'keywords': ['grubhub'],
        'category': 'food'
    },
    'airbnb': {
        'domains': ['airbnb.com', 'airbnb'],
        'android': ['com.airbnb.android'],
        'keywords': ['airbnb'],
        'category': 'travel'
    },
    'booking': {
        'domains': ['booking.com', 'booking'],
        'android': ['com.booking'],
        'keywords': ['booking'],
        'category': 'travel'
    },
    'expedia': {
        'domains': ['expedia.com', 'expedia'],
        'android': ['com.expedia.bookings'],
        'keywords': ['expedia'],
        'category': 'travel'
    },
    'tinder': {
        'domains': ['tinder.com', 'tinder'],
        'android': ['com.tinder'],
        'keywords': ['tinder'],
        'category': 'dating'
    },
    'bumble': {
        'domains': ['bumble.com', 'bumble'],
        'android': ['com.bumble.app'],
        'keywords': ['bumble'],
        'category': 'dating'
    },
    'onlyfans': {
        'domains': ['onlyfans.com', 'onlyfans'],
        'keywords': ['onlyfans', 'of'],
        'category': 'adult'
    },
    'pornhub': {
        'domains': ['pornhub.com', 'pornhub'],
        'keywords': ['pornhub', 'ph'],
        'category': 'adult'
    },
    'mercadolibre': {
        'domains': ['mercadolibre.com', 'mercadolivre.com', 'mercadopago.com', 'mercadolibre.com.mx',
                    'mercadolibre.com.ar', 'mercadolibre.com.co', 'mercadolibre.cl'],
        'android': ['com.mercadolibre', 'com.mercadopago.wallet'],
        'keywords': ['mercadolibre', 'mercadolivre', 'mercadopago', 'meli', 'ml'],
        'category': 'shopping'
    },
    'ebay': {
        'domains': ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay'],
        'android': ['com.ebay.mobile'],
        'keywords': ['ebay'],
        'category': 'shopping'
    },
    'aliexpress': {
        'domains': ['aliexpress.com', 'aliexpress'],
        'android': ['com.alibaba.aliexpresshd'],
        'keywords': ['aliexpress', 'ali'],
        'category': 'shopping'
    },
    'etsy': {
        'domains': ['etsy.com', 'etsy'],
        'android': ['com.etsy.android'],
        'keywords': ['etsy'],
        'category': 'shopping'
    },
    'walmart': {
        'domains': ['walmart.com', 'walmart'],
        'android': ['com.walmart.android'],
        'keywords': ['walmart'],
        'category': 'shopping'
    },
    'cineplanet': {
        'domains': ['cineplanet.com.pe', 'cineplanet'],
        'android': ['com.cineplanet'],
        'keywords': ['cineplanet'],
        'category': 'entertainment'
    },
    'worldcoin': {
        'domains': ['worldcoin.org', 'worldcoin', 'world.org'],
        'android': ['com.worldcoin'],
        'keywords': ['worldcoin', 'wld'],
        'category': 'finance'
    },
    'rappi': {
        'domains': ['rappi.com', 'rappi'],
        'android': ['com.grability.rappi'],
        'keywords': ['rappi'],
        'category': 'food'
    }
}

SYSTEM_EXTENSIONS = ('.exe', '.dll', '.sys', '.bat', '.cmd', '.msi', '.mca', '.db', '.sqlite', '.log', '.tmp', '.bak')

def print_banner():
    print("\n" + "=" * 70)
    print("     ██████╗ ██████╗ ███████╗██████╗     ███████╗██╗  ██╗")
    print("    ██╔════╝██╔═══██╗██╔════╝██╔══██╗    ██╔════╝╚██╗██╔╝")
    print("    ██║     ██║   ██║███████╗██████╔╝    █████╗   ╚███╔╝ ")
    print("    ██║     ██║   ██║╚════██║██╔═══╝     ██╔══╝   ██╔██╗ ")
    print("    ╚██████╗╚██████╔╝███████║██║         ███████╗██╔╝ ██╗")
    print("     ╚═════╝ ╚═════╝ ╚══════╝╚═╝         ╚══════╝╚═╝  ╚═╝")
    print("=" * 70)
    print("          ADVANCED CREDENTIAL EXTRACTOR v5.0 ULTIMATE")
    print("=" * 70)
    print("  [+] 100+ Supported Sites (Web + Android + iOS + Desktop)")
    print("  [+] Multi-format: TXT, JSON, CSV, XML, SQLite, Browser DBs")
    print("  [+] Smart Category Detection (Streaming, Gaming, Finance...)")
    print("  [+] Password Strength & Reuse Analysis")
    print("  [+] Multi-language Credential Field Detection")
    print("=" * 70 + "\n")

def is_git_url(val):
    if not val: return False
    v = val.lower()
    for pattern in GIT_PATTERNS:
        if re.search(pattern, v, re.I):
            return True
    if '.git' in v and ('@' in v or 'github' in v or 'gitlab' in v):
        return True
    return False

def is_system_garbage(val):
    if not val: return True
    v = val.lower().strip()
    if v.endswith(SYSTEM_EXTENSIONS): return True
    if re.match(r'^[a-f0-9]{40,}$', v, re.I): return True
    if re.match(r'^\{?[a-f0-9-]{36}\}?$', v, re.I): return True
    if v.startswith(('c:\\', 'd:\\', 'file://')): return True
    if re.match(r'^\d+x\d+$', v): return True
    if any(x in v for x in ['windows nt', 'amd64', 'x86_64', 'nvidia geforce', 'intel core']):
        if len(v) > 25: return True
    if v.startswith('utc') or 'timezone' in v: return True
    if '","' in val or "','" in val: return True
    return False

def is_valid_username(u):
    if not u: return False
    u = str(u).strip()
    if len(u) < 3 or len(u) > 60: return False
    if u.lower().startswith(('http://', 'https://', 'www.', 'ftp://', 'file://', 'pid:', 'hwid:', 'guid:')): return False
    if u.upper().startswith('PID'): return False
    if is_git_url(u): return False
    if is_system_garbage(u): return False
    if u.lower() in GARBAGE_USERNAMES: return False
    if u in GARBAGE_NUMBERS: return False
    if HEX_ID_RE.match(u): return False
    
    if EMAIL_RE.match(u):
        if u.lower().endswith('.git'): return False
        return True
    
    clean_phone = u.replace(' ', '').replace('-', '').replace('+', '').replace('(', '').replace(')', '')
    if clean_phone.isdigit():
        if len(clean_phone) >= 7 and len(clean_phone) <= 15:
            if clean_phone not in GARBAGE_NUMBERS: return True
        return False
    
    if USERNAME_RE.match(u):
        return True
    
    if re.match(r'^[a-zA-Z0-9._@+-]{3,50}$', u):
        return True
    
    return False

def is_valid_password(p):
    if not p: return False
    p = str(p).strip()
    ln = len(p)
    if ln < 4 or ln > 60: return False
    if p.lower() in GARBAGE_PASSWORDS: return False
    if p in GARBAGE_NUMBERS: return False
    if is_git_url(p): return False
    if p.endswith(('.git', '.exe', '.dll', '.txt', '.json', '.xml', '.html', '.css', '.js', '.php')): return False
    if p.startswith(('eyJ', 'Bearer ', 'Basic ', '{"', '"}', '[{', '}]')): return False
    if '==' in p and ln > 30: return False
    if p.count('=') > 2: return False
    
    garbage_words = ['animation', 'function', 'prototype', 'inherits', 'require', 'module', 
                     'exports', 'import', 'return', 'undefined', 'console', 'window', 'document',
                     'intel core', 'amd ryzen', 'nvidia', 'geforce', 'radeon',
                     'courrier', 'catalogue', 'shipping', 'tracking', 'warranty',
                     '\\u003c', '\\u003e', '\u003c', '\u003e', '<<', '>>']
    if any(w in p.lower() for w in garbage_words): return False
    if p.startswith(('http://', 'https://', 'www.', 'ftp://', '/', '\\')): return False
    if re.match(r'^[a-f0-9]{40,}$', p, re.I): return False
    if '(R)' in p or '(TM)' in p or '(C)' in p: return False
    
    weird_chars = sum(1 for c in p if ord(c) < 32 or ord(c) > 126)
    if weird_chars > 0: return False
    if p.count('{') > 0 or p.count('}') > 0: return False
    if p.count('<') > 0 or p.count('>') > 0: return False
    
    return True

def analyze_password_strength(password):
    """Analyze password strength and return score + details."""
    score = 0
    details = []
    
    length = len(password)
    if length >= 16:
        score += 3
        details.append("Long (16+)")
    elif length >= 12:
        score += 2
        details.append("Good length (12+)")
    elif length >= 8:
        score += 1
        details.append("Adequate (8+)")
    else:
        details.append("Short (<8)")
    
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
        details.append("Uppercase")
    if re.search(r'\d', password):
        score += 1
        details.append("Numbers")
    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        score += 2
        details.append("Symbols")
    
    common_patterns = ['123', 'abc', 'qwerty', 'password', 'pass', '111', '000', 'admin']
    for pattern in common_patterns:
        if pattern in password.lower():
            score -= 1
            details.append("Common pattern")
            break
    
    if score >= 6:
        strength = "STRONG"
    elif score >= 4:
        strength = "MEDIUM"
    elif score >= 2:
        strength = "WEAK"
    else:
        strength = "VERY WEAK"
    
    return {
        'score': max(0, score),
        'strength': strength,
        'details': details
    }

def extract_android_package(url):
    """Extract Android package name from android:// URL."""
    if not url:
        return None
    
    match = re.search(r'@([a-zA-Z0-9_.]+)/?$', url)
    if match:
        return match.group(1).lower()
    
    match = re.search(r'android://[^@]+@([a-zA-Z0-9_.]+)', url)
    if match:
        return match.group(1).lower()
    
    return None

def extract_ios_bundle(url):
    """Extract iOS bundle ID from app URL."""
    if not url:
        return None
    
    match = re.search(r'(?:ios|iphone|ipad)://[^/]*@?([a-zA-Z0-9._-]+)', url, re.I)
    if match:
        return match.group(1).lower()
    
    return None

def url_to_site(url):
    """Extract site name from URL - handles all URL formats."""
    if not url:
        return None
    
    url_lower = url.lower()
    
    if url_lower.startswith('android://'):
        package = extract_android_package(url)
        if package:
            for site_name, site_data in POPULAR_SITES.items():
                android_packages = site_data.get('android', [])
                for pkg in android_packages:
                    if pkg.lower() in package or package in pkg.lower():
                        return site_name
                keywords = site_data.get('keywords', [])
                for kw in keywords:
                    if kw.lower() in package:
                        return site_name
            for site_name, site_data in POPULAR_SITES.items():
                if site_name in package:
                    return site_name
        return None
    
    if 'ios://' in url_lower or 'iphone://' in url_lower:
        bundle = extract_ios_bundle(url)
        if bundle:
            for site_name, site_data in POPULAR_SITES.items():
                ios_bundles = site_data.get('ios', [])
                for bid in ios_bundles:
                    if bid.lower() in bundle or bundle in bid.lower():
                        return site_name
        return None
    
    for site_name, site_data in POPULAR_SITES.items():
        domains = site_data.get('domains', [])
        for domain in domains:
            domain_lower = domain.lower()
            pattern = r'(?:^|[:/])(?:www\.)?' + re.escape(domain_lower) + r'(?:[:/]|$)'
            if re.search(pattern, url_lower):
                return site_name
        
        keywords = site_data.get('keywords', [])
        for kw in keywords:
            pattern = r'(?:^|[./])' + re.escape(kw.lower()) + r'(?:[./]|$)'
            if re.search(pattern, url_lower):
                return site_name
    
    match = re.search(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+)\.', url)
    if match:
        domain = match.group(1).lower()
        if domain not in ['www', 'http', 'https', 'login', 'auth', 'account', 'api', 'm', 'mobile', 
                          'sso', 'id', 'accounts', 'signin', 'signup', 'register', 'oauth', 'secure']:
            return domain
    
    return None

def get_site_category(site_name):
    """Get primary category for a site."""
    if not site_name:
        return 'unknown'
    
    site_lower = site_name.lower()
    site_data = POPULAR_SITES.get(site_lower, {})
    if site_data:
        if 'categories' in site_data:
            return site_data['categories'][0]
        return site_data.get('category', 'other')
    
    for category, sites in SITE_CATEGORIES.items():
        if site_lower in sites:
            return category
    
    return 'other'

def get_site_categories(site_name):
    """Get all categories for a site (some sites belong to multiple)."""
    if not site_name:
        return ['unknown']
    
    site_lower = site_name.lower()
    categories = set()
    
    site_data = POPULAR_SITES.get(site_lower, {})
    if site_data:
        if 'categories' in site_data:
            categories.update(site_data['categories'])
        elif 'category' in site_data:
            categories.add(site_data['category'])
    
    for category, sites in SITE_CATEGORIES.items():
        if site_lower in sites:
            categories.add(category)
    
    return list(categories) if categories else ['other']

def site_matches_category(site_name, target_categories):
    """Check if a site belongs to any of the target categories."""
    if not site_name or not target_categories:
        return False
    
    site_categories = get_site_categories(site_name)
    return any(cat in target_categories for cat in site_categories)

def matches_target(url, site, target_sites, target_categories=None, username=None, password=None):
    """Check if a URL/site matches any of the target sites or categories.
    
    ADVANCED MATCHING:
    - Searches URL, site name, username, and all data for ANY match
    - Works with ANY search term, not just predefined sites
    - Case-insensitive matching
    """
    if not target_sites and not target_categories:
        return True
    
    if target_categories:
        if site_matches_category(site, target_categories):
            return True
        if url:
            detected_site = url_to_site(url)
            if detected_site and site_matches_category(detected_site, target_categories):
                return True
    
    if target_sites:
        if site and site in target_sites:
            return True
        
        for target in target_sites:
            target_lower = target.lower()
            
            if url:
                url_lower = url.lower()
                if target_lower in url_lower:
                    return True
                
                if url_lower.startswith('android://'):
                    package = extract_android_package(url)
                    if package and target_lower in package:
                        return True
            
            if site and target_lower in site.lower():
                return True
            
            if username and target_lower in username.lower():
                return True
            
            site_data = POPULAR_SITES.get(target, {})
            if site_data:
                domains = site_data.get('domains', [])
                keywords = site_data.get('keywords', [])
                android_pkgs = site_data.get('android', [])
                ios_pkgs = site_data.get('ios', [])
                
                all_patterns = domains + keywords + android_pkgs + ios_pkgs
                
                for pattern in all_patterns:
                    pattern_lower = pattern.lower()
                    if url and pattern_lower in url.lower():
                        return True
                    if site and pattern_lower in site.lower():
                        return True
    
    return False

def extract_credential_blocks(text, target_sites=None, target_categories=None):
    """Extract credentials with their associated URLs from structured blocks."""
    results = []
    
    url_labels_pattern = '|'.join(re.escape(l) for l in URL_LABELS)
    user_labels_pattern = '|'.join(re.escape(l) for l in USER_LABELS_MULTI)
    pass_labels_pattern = '|'.join(re.escape(l) for l in PASS_LABELS_MULTI)
    
    url_pattern = re.compile(rf'(?:^|\n)\s*(?:{url_labels_pattern})\s*[:=]\s*([^\n\r]+)', re.I)
    user_pattern = re.compile(rf'(?:^|\n)\s*(?:{user_labels_pattern})\s*[:=]\s*([^\n\r]+)', re.I)
    pass_pattern = re.compile(rf'(?:^|\n)\s*(?:{pass_labels_pattern})\s*[:=]\s*([^\n\r]+)', re.I)
    
    blocks = re.split(r'\n\s*\n|\r\n\s*\r\n|={3,}|-{3,}|\*{3,}|Application:|Browser:|Profile:', text)
    
    for block in blocks:
        if len(block.strip()) < 10:
            continue
            
        url_match = url_pattern.search(block)
        user_match = user_pattern.search(block)
        pass_match = pass_pattern.search(block)
        
        if user_match and pass_match:
            username = user_match.group(1).strip()
            password = pass_match.group(1).strip()
            url = url_match.group(1).strip() if url_match else None
            
            if is_valid_username(username) and is_valid_password(password):
                site = url_to_site(url) if url else None
                
                if target_sites or target_categories:
                    if not matches_target(url, site, target_sites, target_categories, username=username):
                        continue
                
                category = get_site_category(site)
                strength = analyze_password_strength(password)
                
                results.append({
                    'username': username,
                    'password': password,
                    'url': url,
                    'site': site,
                    'category': category,
                    'strength': strength
                })
    
    return results

def extract_json_credentials(text, target_sites=None, target_categories=None):
    """Extract credentials from JSON format."""
    results = []
    
    try:
        data = json.loads(text)
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = [data]
            for key in ['logins', 'credentials', 'passwords', 'accounts', 'entries', 'data']:
                if key in data and isinstance(data[key], list):
                    items = data[key]
                    break
        else:
            return results
        
        for item in items:
            if not isinstance(item, dict):
                continue
            
            username = None
            password = None
            url = None
            
            for key in ['username', 'user', 'login', 'email', 'mail', 'account', 'id', 'name']:
                if key in item:
                    username = str(item[key]).strip()
                    break
            
            for key in ['password', 'pass', 'pwd', 'secret', 'key']:
                if key in item:
                    password = str(item[key]).strip()
                    break
            
            for key in ['url', 'host', 'site', 'domain', 'origin', 'hostname', 'uri']:
                if key in item:
                    url = str(item[key]).strip()
                    break
            
            if username and password and is_valid_username(username) and is_valid_password(password):
                site = url_to_site(url) if url else None
                
                if target_sites or target_categories:
                    if not matches_target(url, site, target_sites, target_categories, username=username):
                        continue
                
                category = get_site_category(site)
                strength = analyze_password_strength(password)
                
                results.append({
                    'username': username,
                    'password': password,
                    'url': url,
                    'site': site,
                    'category': category,
                    'strength': strength
                })
    except:
        pass
    
    return results

def extract_csv_credentials(text, target_sites=None, target_categories=None):
    """Extract credentials from CSV format."""
    results = []
    
    try:
        lines = text.strip().split('\n')
        if len(lines) < 2:
            return results
        
        header = lines[0].lower()
        if ',' not in header and '\t' not in header:
            return results
        
        delimiter = ',' if ',' in header else '\t'
        reader = csv.DictReader(lines, delimiter=delimiter)
        
        for row in reader:
            row_lower = {k.lower().strip(): v for k, v in row.items() if k}
            
            username = None
            password = None
            url = None
            
            for key in ['username', 'user', 'login', 'email', 'mail', 'account', 'name']:
                if key in row_lower:
                    username = str(row_lower[key]).strip()
                    break
            
            for key in ['password', 'pass', 'pwd', 'secret']:
                if key in row_lower:
                    password = str(row_lower[key]).strip()
                    break
            
            for key in ['url', 'host', 'site', 'domain', 'origin', 'website']:
                if key in row_lower:
                    url = str(row_lower[key]).strip()
                    break
            
            if username and password and is_valid_username(username) and is_valid_password(password):
                site = url_to_site(url) if url else None
                
                if target_sites or target_categories:
                    if not matches_target(url, site, target_sites, target_categories, username=username):
                        continue
                
                category = get_site_category(site)
                strength = analyze_password_strength(password)
                
                results.append({
                    'username': username,
                    'password': password,
                    'url': url,
                    'site': site,
                    'category': category,
                    'strength': strength
                })
    except:
        pass
    
    return results

def extract_sqlite_credentials(db_path, target_sites=None, target_categories=None):
    """Extract credentials from SQLite database (browser password DBs)."""
    results = []
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [t[0] for t in cursor.fetchall()]
        
        login_tables = ['logins', 'moz_logins', 'credentials', 'passwords', 'autofill', 'saved_logins']
        
        for table in tables:
            if table.lower() in login_tables or 'login' in table.lower() or 'password' in table.lower():
                try:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [col[1].lower() for col in cursor.fetchall()]
                    
                    url_col = None
                    user_col = None
                    pass_col = None
                    
                    for col in columns:
                        if col in ['origin_url', 'hostname', 'url', 'host', 'site', 'domain']:
                            url_col = col
                        if col in ['username_value', 'username', 'user', 'login', 'encryptedusername']:
                            user_col = col
                        if col in ['password_value', 'password', 'pass', 'encryptedpassword']:
                            pass_col = col
                    
                    if user_col and pass_col:
                        if url_col:
                            cursor.execute(f"SELECT {url_col}, {user_col}, {pass_col} FROM {table}")
                        else:
                            cursor.execute(f"SELECT NULL, {user_col}, {pass_col} FROM {table}")
                        
                        for row in cursor.fetchall():
                            url, username, password = row[0], row[1], row[2]
                            
                            if isinstance(password, bytes):
                                try:
                                    password = password.decode('utf-8', errors='ignore')
                                except:
                                    continue
                            
                            if isinstance(username, bytes):
                                try:
                                    username = username.decode('utf-8', errors='ignore')
                                except:
                                    continue
                            
                            if username and password and is_valid_username(str(username)) and is_valid_password(str(password)):
                                site = url_to_site(url) if url else None
                                
                                if target_sites or target_categories:
                                    if not matches_target(url, site, target_sites, target_categories, username=str(username)):
                                        continue
                                
                                category = get_site_category(site)
                                strength = analyze_password_strength(str(password))
                                
                                results.append({
                                    'username': str(username),
                                    'password': str(password),
                                    'url': url,
                                    'site': site,
                                    'category': category,
                                    'strength': strength
                                })
                except:
                    pass
        
        conn.close()
    except:
        pass
    
    return results

def extract_direct_combos(text, default_site=None, target_sites=None, target_categories=None):
    """Extract email:pass, user:pass, phone:pass patterns."""
    results = []
    
    patterns = [
        r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[:|\|;]\s*([^\s:|\|;\n\r\t]{4,60})',
        r'(\+?\d{10,15})\s*[:|\|;]\s*([^\s:|\|;\n\r\t]{4,60})',
        r'([a-zA-Z][a-zA-Z0-9._-]{2,30})\s*[:|\|;]\s*([^\s:|\|;\n\r\t]{4,60})',
    ]
    
    for pattern in patterns:
        for m in re.finditer(pattern, text, re.I | re.M):
            user, pw = m.group(1).strip(), m.group(2).strip()
            if is_valid_username(user) and is_valid_password(pw):
                site = default_site
                category = get_site_category(site)
                
                if target_sites or target_categories:
                    if not matches_target(None, site, target_sites, target_categories, username=user):
                        continue
                
                strength = analyze_password_strength(pw)
                
                results.append({
                    'username': user,
                    'password': pw,
                    'url': None,
                    'site': site,
                    'category': category,
                    'strength': strength
                })
    
    return results

def process_text(text, filename="", target_sites=None, target_categories=None):
    """Extract credentials from text with format auto-detection."""
    all_creds = []
    
    text_stripped = text.strip()
    
    if text_stripped.startswith('{') or text_stripped.startswith('['):
        json_creds = extract_json_credentials(text, target_sites, target_categories)
        if json_creds:
            all_creds.extend(json_creds)
            return all_creds
    
    if ',' in text_stripped.split('\n')[0] if '\n' in text_stripped else False:
        first_line = text_stripped.split('\n')[0].lower()
        if any(x in first_line for x in ['username', 'password', 'email', 'url', 'login']):
            csv_creds = extract_csv_credentials(text, target_sites, target_categories)
            if csv_creds:
                all_creds.extend(csv_creds)
                return all_creds
    
    block_creds = extract_credential_blocks(text, target_sites, target_categories)
    all_creds.extend(block_creds)
    
    site_from_filename = None
    filename_lower = filename.lower()
    for site_name, site_data in POPULAR_SITES.items():
        domains = site_data.get('domains', [])
        keywords = site_data.get('keywords', [])
        all_patterns = domains + keywords
        for pattern in all_patterns:
            if pattern.lower() in filename_lower:
                site_from_filename = site_name
                break
        if site_from_filename:
            break
    
    direct_creds = extract_direct_combos(text, site_from_filename, target_sites, target_categories)
    
    block_combos = {(c['username'].lower(), c['password']) for c in block_creds}
    for cred in direct_creds:
        key = (cred['username'].lower(), cred['password'])
        if key not in block_combos:
            all_creds.append(cred)
    
    return all_creds

def check_zip_encrypted(zip_path):
    """Check if ZIP file is password protected."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for fi in zf.filelist:
                if fi.flag_bits & 0x1:  # Encrypted flag
                    return True
            # Try to read first file to detect encryption
            for fi in zf.filelist:
                if not fi.is_dir():
                    try:
                        with zf.open(fi.filename) as f:
                            f.read(1)
                        return False
                    except RuntimeError as e:
                        if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                            return True
    except:
        pass
    return False

def try_zip_passwords(zip_path, passwords):
    """Try multiple passwords on a ZIP file."""
    for pwd in passwords:
        try:
            pwd_bytes = pwd.encode('utf-8') if isinstance(pwd, str) else pwd
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for fi in zf.filelist:
                    if not fi.is_dir():
                        with zf.open(fi.filename, pwd=pwd_bytes) as f:
                            f.read(1)
                        return pwd_bytes
        except:
            continue
    return None

def _process_zip_file_data(args):
    """Helper for parallel zip processing."""
    filename, data, target_sites, target_categories = args
    try:
        if is_binary_content(data):
            return []
        text = data.decode('utf-8', errors='ignore')
        if not text:
            text = data.decode('latin-1', errors='ignore')
        if text:
            return process_text(text, filename, target_sites, target_categories)
    except:
        pass
    return []

def process_zip_with_password(zip_path, all_creds, target_sites=None, target_categories=None, parent_password=None):
    """Process ZIP with optional inherited password from parent ZIP."""
    zip_password = parent_password
    encrypted_count = 0
    
    try:
        # Check if ZIP is encrypted and we don't have a password
        if check_zip_encrypted(zip_path):
            if parent_password:
                # Try parent password first
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        for fi in zf.filelist:
                            if not fi.is_dir():
                                with zf.open(fi.filename, pwd=parent_password) as f:
                                    f.read(1)
                                break
                    print(f"  [+] Using parent password for nested ZIP")
                except:
                    # Parent password didn't work, ask user
                    print(f"  [!] Nested ZIP needs different password!")
                    user_pwd = input("  [?] Enter nested ZIP password (or press Enter to skip): ").strip()
                    if user_pwd:
                        zip_password = user_pwd.encode('utf-8')
                    else:
                        print(f"  [!] Skipping encrypted nested ZIP")
                        return
            else:
                print(f"  [!] Nested ZIP is password protected!")
                user_pwd = input("  [?] Enter ZIP password (or press Enter to skip): ").strip()
                if user_pwd:
                    zip_password = user_pwd.encode('utf-8')
                else:
                    print(f"  [!] Skipping encrypted ZIP")
                    return
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            all_files = [f for f in zf.filelist if not f.is_dir()]
            
            # Separate file types
            nested_zips = []
            db_files = []
            text_files = []
            skipped = 0
            
            for fi in all_files:
                if fi.file_size > 50 * 1024 * 1024:
                    skipped += 1
                elif fi.filename.lower().endswith('.zip'):
                    nested_zips.append(fi)
                elif fi.filename.endswith('.db') or fi.filename.endswith('.sqlite'):
                    db_files.append(fi)
                elif is_likely_text_file(fi.filename, fi.file_size):
                    text_files.append(fi)
                else:
                    skipped += 1
            
            print(f"  [NESTED] {len(text_files)} text, {len(db_files)} db, {len(nested_zips)} nested, {skipped} skip")
            
            # Process nested ZIPs recursively
            for fi in nested_zips:
                print(f"  [*] Found nested ZIP: {fi.filename}")
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
                        with zf.open(fi.filename, pwd=zip_password) as f:
                            tmp.write(f.read())
                        tmp_path = tmp.name
                    process_zip_with_password(tmp_path, all_creds, target_sites, target_categories, zip_password)
                    os.unlink(tmp_path)
                except Exception as e:
                    print(f"  [!] Error with nested ZIP: {e}")
            
            # Process DB files
            for fi in db_files:
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                        with zf.open(fi.filename, pwd=zip_password) as f:
                            tmp.write(f.read())
                        tmp_path = tmp.name
                    creds = extract_sqlite_credentials(tmp_path, target_sites, target_categories)
                    all_creds.extend(creds)
                    os.unlink(tmp_path)
                except:
                    pass
            
            # Read all text files
            file_data = []
            for fi in text_files:
                try:
                    with zf.open(fi.filename, pwd=zip_password) as f:
                        data = f.read()
                        file_data.append((fi.filename, data, target_sites, target_categories))
                except:
                    pass
            
            # Process in parallel
            if file_data:
                with ThreadPoolExecutor(max_workers=200) as executor:
                    futures = {executor.submit(_process_zip_file_data, args): args[0] for args in file_data}
                    for future in as_completed(futures):
                        try:
                            creds = future.result()
                            if creds:
                                all_creds.extend(creds)
                        except:
                            pass
                            
    except Exception as e:
        print(f"  [ERROR] {e}")

def process_zip(zip_path, all_creds, target_sites=None, target_categories=None):
    zip_password = None
    encrypted_count = 0
    
    try:
        # Check if ZIP is encrypted
        if check_zip_encrypted(zip_path):
            print(f"  [!] ZIP file is password protected!")
            user_pwd = input("  [?] Enter ZIP password (or press Enter to skip): ").strip()
            if user_pwd:
                try:
                    zip_password = user_pwd.encode('utf-8')
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        for fi in zf.filelist:
                            if not fi.is_dir():
                                with zf.open(fi.filename, pwd=zip_password) as f:
                                    f.read(1)
                                break
                    print(f"  [+] Password accepted!")
                except:
                    print(f"  [!] Invalid password. Skipping encrypted files.")
                    zip_password = None
            else:
                print(f"  [!] No password provided. Skipping encrypted files.")
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            all_files = [f for f in zf.filelist if not f.is_dir()]
            
            # Separate file types
            nested_zips = []
            db_files = []
            text_files = []
            skipped = 0
            
            for fi in all_files:
                if fi.file_size > 50 * 1024 * 1024:
                    skipped += 1
                elif fi.filename.lower().endswith('.zip'):
                    nested_zips.append(fi)
                elif fi.filename.endswith('.db') or fi.filename.endswith('.sqlite'):
                    db_files.append(fi)
                elif is_likely_text_file(fi.filename, fi.file_size):
                    text_files.append(fi)
                else:
                    skipped += 1
            
            print(f"  [ZIP] {len(text_files)} text, {len(db_files)} db, {len(nested_zips)} nested zips, {skipped} skipped")
            
            # Process nested ZIPs first (recursive)
            for fi in nested_zips:
                print(f"  [*] Found nested ZIP: {fi.filename}")
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
                        with zf.open(fi.filename, pwd=zip_password) as f:
                            tmp.write(f.read())
                        tmp_path = tmp.name
                    # Recursively process nested ZIP - pass the same password
                    process_zip_with_password(tmp_path, all_creds, target_sites, target_categories, zip_password)
                    os.unlink(tmp_path)
                except RuntimeError as e:
                    if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                        encrypted_count += 1
                        print(f"  [!] Nested ZIP is password protected: {fi.filename}")
                except Exception as e:
                    print(f"  [!] Error with nested ZIP: {e}")
            
            # Process DB files sequentially
            for fi in db_files:
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                        with zf.open(fi.filename, pwd=zip_password) as f:
                            tmp.write(f.read())
                        tmp_path = tmp.name
                    creds = extract_sqlite_credentials(tmp_path, target_sites, target_categories)
                    all_creds.extend(creds)
                    os.unlink(tmp_path)
                except RuntimeError as e:
                    if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                        encrypted_count += 1
                except:
                    pass
            
            # Read all text files
            print(f"  [*] Reading files...")
            file_data = []
            for fi in text_files:
                try:
                    with zf.open(fi.filename, pwd=zip_password) as f:
                        data = f.read()
                        file_data.append((fi.filename, data, target_sites, target_categories))
                except RuntimeError as e:
                    if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                        encrypted_count += 1
                except:
                    pass
            
            # Process in parallel - 200 THREADS
            print(f"  [*] Extracting credentials (200 threads)...")
            found_count = [0]
            
            with ThreadPoolExecutor(max_workers=200) as executor:
                futures = {executor.submit(_process_zip_file_data, args): args[0] for args in file_data}
                processed = 0
                
                for future in as_completed(futures):
                    processed += 1
                    try:
                        creds = future.result()
                        if creds:
                            all_creds.extend(creds)
                            found_count[0] += len(creds)
                    except:
                        pass
                    
                    if processed % 500 == 0 or processed == len(futures):
                        pct = int(processed / max(len(futures), 1) * 100)
                        print(f"  [{pct:3d}%] {processed}/{len(futures)} | Found: {found_count[0]} creds")
            
            if encrypted_count > 0:
                print(f"  [!] Skipped {encrypted_count} encrypted files")
                
    except Exception as e:
        print(f"  [ERROR] {e}")

def _process_folder_file(args):
    """Helper for parallel folder processing."""
    fpath, target_sites, target_categories = args
    try:
        if not is_likely_text_file(fpath):
            return []
        text = read_file(fpath)
        if text:
            return process_text(text, fpath, target_sites, target_categories)
    except:
        pass
    return []

def process_folder(folder_path, all_creds, target_sites=None, target_categories=None):
    # Collect and categorize files
    text_files = []
    zip_files = []
    db_files = []
    
    for root, dirs, files in os.walk(folder_path):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for f in files:
            if f.startswith('.'):
                continue
            fpath = os.path.join(root, f)
            if fpath.endswith('.zip'):
                zip_files.append(fpath)
            elif fpath.endswith('.db') or fpath.endswith('.sqlite'):
                db_files.append(fpath)
            elif is_likely_text_file(f):
                text_files.append(fpath)
    
    print(f"  [FOLDER] {len(text_files)} text, {len(zip_files)} zips, {len(db_files)} db files")
    
    # Process ZIP files (they have their own parallel processing)
    for zp in zip_files:
        process_zip(zp, all_creds, target_sites, target_categories)
    
    # Process DB files sequentially (thread-unsafe)
    for dbf in db_files:
        try:
            creds = extract_sqlite_credentials(dbf, target_sites, target_categories)
            all_creds.extend(creds)
        except:
            pass
    
    # Process text files in parallel - 200 THREADS
    if text_files:
        print(f"  [*] Extracting from text files (200 threads)...")
        found_count = [0]
        
        with ThreadPoolExecutor(max_workers=200) as executor:
            args_list = [(fp, target_sites, target_categories) for fp in text_files]
            futures = {executor.submit(_process_folder_file, args): args[0] for args in args_list}
            processed = 0
            
            for future in as_completed(futures):
                processed += 1
                try:
                    creds = future.result()
                    if creds:
                        all_creds.extend(creds)
                        found_count[0] += len(creds)
                except:
                    pass
                
                if processed % 500 == 0 or processed == len(futures):
                    pct = int(processed / max(len(futures), 1) * 100)
                    print(f"  [{pct:3d}%] {processed}/{len(futures)} | Found: {found_count[0]} creds")
    
    print(f"  [*] Total: {len(all_creds)} credentials found")

def read_file(path):
    for enc in ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1', 'utf-16']:
        try:
            with open(path, 'r', encoding=enc, errors='ignore') as f:
                return f.read()
        except: pass
    return ""

def parse_target_sites(user_input):
    """Parse user input for target sites with comprehensive pattern matching."""
    user_input = user_input.lower().strip()
    user_input = re.sub(r'[,;|]', ' ', user_input)
    user_input = user_input.replace(':', ' ')
    
    parts = user_input.split()
    targets = set()
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
        
        part = re.sub(r'^(https?://)?(www\.)?', '', part)
        part = re.sub(r'\.(com|net|org|io|tv|gg|co|app|me|us|uk)/?$', '', part)
        
        matched = False
        for site_name, site_data in POPULAR_SITES.items():
            if part == site_name:
                targets.add(site_name)
                matched = True
                break
            
            domains = site_data.get('domains', [])
            keywords = site_data.get('keywords', [])
            android_pkgs = site_data.get('android', [])
            ios_pkgs = site_data.get('ios', [])
            desktop_apps = site_data.get('desktop', [])
            
            all_patterns = domains + keywords + android_pkgs + ios_pkgs + desktop_apps
            
            for pattern in all_patterns:
                if part in pattern.lower() or pattern.lower() in part:
                    targets.add(site_name)
                    matched = True
                    break
            
            if matched:
                break
        
        if not matched and len(part) >= 2:
            targets.add(part)
    
    return targets

def parse_target_categories(user_input):
    """Parse user input for target categories."""
    user_input = user_input.lower().strip()
    user_input = re.sub(r'[,;|:]', ' ', user_input)
    
    parts = user_input.split()
    categories = set()
    
    for part in parts:
        part = part.strip()
        if part in SITE_CATEGORIES:
            categories.add(part)
    
    return categories

def deduplicate_creds(creds):
    """Remove duplicate credentials."""
    seen = set()
    unique = []
    for cred in creds:
        key = (cred['username'].lower(), cred['password'])
        if key not in seen:
            seen.add(key)
            unique.append(cred)
    return unique

def detect_password_reuse(creds):
    """Detect password reuse across different sites/usernames."""
    password_usage = defaultdict(list)
    
    for cred in creds:
        password_usage[cred['password']].append({
            'username': cred['username'],
            'site': cred.get('site', 'unknown')
        })
    
    reused = {pw: accounts for pw, accounts in password_usage.items() if len(accounts) > 1}
    return reused

# ============================================================================
# CREDIT CARD EXTRACTION FUNCTIONS
# ============================================================================

def luhn_check(card_number):
    """Validate card number using Luhn algorithm."""
    digits = [int(d) for d in str(card_number) if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0

def get_card_type(card_number):
    """Identify card type from number."""
    card_num = re.sub(r'[\s-]', '', str(card_number))
    for card_type, pattern in CARD_TYPES.items():
        if pattern.match(card_num):
            return card_type
    return 'unknown'

def clean_card_number(raw):
    """Clean and normalize card number."""
    return re.sub(r'[\s\-\.]', '', str(raw))

def parse_expiration(exp_str):
    """Parse expiration date from various formats. Returns (month, year) or (None, None)."""
    if not exp_str:
        return None, None
    
    exp_str = str(exp_str).strip()
    
    # Format: MM/YYYY or MM/YY
    match = re.match(r'^(\d{1,2})[/\-](\d{2,4})$', exp_str)
    if match:
        month = match.group(1).zfill(2)
        year = match.group(2)
        if len(year) == 2:
            year = '20' + year
        return month, year
    
    # Format: YYYY/MM or YYYY-MM
    match = re.match(r'^(\d{4})[/\-](\d{1,2})$', exp_str)
    if match:
        year = match.group(1)
        month = match.group(2).zfill(2)
        return month, year
    
    # Format: MMYY or MMYYYY
    match = re.match(r'^(\d{2})(\d{2,4})$', exp_str)
    if match:
        month = match.group(1)
        year = match.group(2)
        if len(year) == 2:
            year = '20' + year
        if int(month) <= 12:
            return month, year
    
    # Format: just year YYYY
    match = re.match(r'^(20\d{2})$', exp_str)
    if match:
        return None, match.group(1)
    
    return None, None

def extract_cc_labeled_format(text):
    """Extract CC from labeled format like CardNumber: XXX, CVC: XXX, etc."""
    cards = []
    lines = text.split('\n')
    
    current_card = {}
    context_lines = []
    
    for i, line in enumerate(lines):
        line_lower = line.lower().strip()
        
        # Check for card number labels
        for label in CC_NUMBER_LABELS:
            pattern = re.compile(r'(?:^|[^a-z])' + re.escape(label) + r'\s*[:=]\s*([0-9\s\-]{13,25})', re.I)
            match = pattern.search(line)
            if match:
                num = clean_card_number(match.group(1))
                if len(num) >= 13 and len(num) <= 19:
                    current_card['number'] = num
                    context_lines.append(line.strip())
                break
        
        # Check for CVV labels
        for label in CC_CVV_LABELS:
            pattern = re.compile(r'(?:^|[^a-z])' + re.escape(label) + r'\s*[:=]\s*(\d{3,4})', re.I)
            match = pattern.search(line)
            if match:
                current_card['cvv'] = match.group(1)
                context_lines.append(line.strip())
                break
        
        # Check for expiration labels
        for label in CC_EXP_LABELS:
            pattern = re.compile(r'(?:^|[^a-z])' + re.escape(label) + r'\s*[:=]\s*(\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{1,2}|\d{4,6})', re.I)
            match = pattern.search(line)
            if match:
                month, year = parse_expiration(match.group(1))
                if month:
                    current_card['exp_month'] = month
                if year:
                    current_card['exp_year'] = year
                context_lines.append(line.strip())
                break
        
        # Check for name labels
        for label in CC_NAME_LABELS:
            pattern = re.compile(r'(?:^|[^a-z])' + re.escape(label) + r'\s*[:=]\s*([A-Za-z\s\-\'\.]+)', re.I)
            match = pattern.search(line)
            if match:
                name = match.group(1).strip()
                if len(name) >= 2 and not name.lower() in ['n/a', 'na', 'none', 'null', '']:
                    current_card['name'] = name
                context_lines.append(line.strip())
                break
        
        # If we have a card number and hit empty line or end, save the card
        if (not line.strip() or i == len(lines) - 1) and 'number' in current_card:
            if luhn_check(current_card['number']):
                current_card['context'] = '\n'.join(context_lines)
                current_card['format'] = 'labeled'
                cards.append(current_card.copy())
            current_card = {}
            context_lines = []
    
    # Don't forget last card
    if 'number' in current_card and luhn_check(current_card['number']):
        current_card['context'] = '\n'.join(context_lines)
        current_card['format'] = 'labeled'
        cards.append(current_card)
    
    return cards

def extract_cc_delimited_format(text):
    """Extract CC from pipe/slash/colon delimited formats."""
    cards = []
    
    # Patterns for delimited formats: num|mm|yyyy|cvv or num/mm/yyyy/cvv or num:mm:yyyy:cvv
    # Also handles num|mm|yy|cvv
    delimited_patterns = [
        # Full format: number|month|year|cvv
        re.compile(r'(\d{13,19})\s*[|/:\\]\s*(\d{1,2})\s*[|/:\\]\s*(\d{2,4})\s*[|/:\\]\s*(\d{3,4})'),
        # Format: number|exp|cvv where exp is MMYY or MM/YY
        re.compile(r'(\d{13,19})\s*[|/:\\]\s*(\d{2}[/\-]?\d{2,4})\s*[|/:\\]\s*(\d{3,4})'),
        # Format with expiration like 12/2025
        re.compile(r'(\d{13,19})\s*[|/:\\]\s*(\d{1,2}/\d{2,4})\s*[|/:\\]\s*(\d{3,4})'),
    ]
    
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        for pattern in delimited_patterns:
            match = pattern.search(line)
            if match:
                groups = match.groups()
                card_num = clean_card_number(groups[0])
                
                if len(card_num) >= 13 and len(card_num) <= 19 and luhn_check(card_num):
                    card = {'number': card_num, 'context': line, 'format': 'delimited'}
                    
                    if len(groups) == 4:
                        # num|mm|yyyy|cvv format
                        card['exp_month'] = groups[1].zfill(2)
                        year = groups[2]
                        card['exp_year'] = year if len(year) == 4 else '20' + year
                        card['cvv'] = groups[3]
                    elif len(groups) == 3:
                        # Parse the expiration from second group
                        month, year = parse_expiration(groups[1])
                        if month:
                            card['exp_month'] = month
                        if year:
                            card['exp_year'] = year
                        card['cvv'] = groups[2]
                    
                    cards.append(card)
                    break
    
    return cards

def extract_cc_newline_format(text):
    """Extract CC from newline-separated format (card on one line, exp on next, etc)."""
    cards = []
    lines = [l.strip() for l in text.split('\n') if l.strip()]
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Check if current line is a card number
        card_match = CC_NUMBER_RE.search(line) or CC_NUMBER_SPACED_RE.search(line)
        if card_match:
            card_num = clean_card_number(card_match.group())
            
            if len(card_num) >= 13 and len(card_num) <= 19 and luhn_check(card_num):
                card = {'number': card_num, 'format': 'newline'}
                context_lines = [line]
                
                # Look ahead for exp month, year, cvv (up to 4 lines)
                lookahead = min(4, len(lines) - i - 1)
                j = 1
                
                while j <= lookahead:
                    next_line = lines[i + j].strip()
                    context_lines.append(next_line)
                    
                    # Check if it's a 2-digit month
                    if re.match(r'^(0?[1-9]|1[0-2])$', next_line) and 'exp_month' not in card:
                        card['exp_month'] = next_line.zfill(2)
                    # Check if it's a year (2 or 4 digit)
                    elif re.match(r'^(20)?\d{2}$', next_line) and 'exp_year' not in card:
                        year = next_line
                        if len(year) == 2:
                            year = '20' + year
                        card['exp_year'] = year
                    # Check if it's a CVV (3-4 digits)
                    elif re.match(r'^\d{3,4}$', next_line) and 'cvv' not in card:
                        card['cvv'] = next_line
                    # Check for combined exp format MM/YY or MM/YYYY
                    elif re.match(r'^\d{1,2}[/\-]\d{2,4}$', next_line):
                        month, year = parse_expiration(next_line)
                        if month:
                            card['exp_month'] = month
                        if year:
                            card['exp_year'] = year
                    # If we hit another card number or unrelated content, stop
                    elif CC_NUMBER_RE.search(next_line):
                        break
                    
                    j += 1
                    
                    # If we have all components, stop looking
                    if all(k in card for k in ['exp_month', 'exp_year', 'cvv']):
                        break
                
                card['context'] = '\n'.join(context_lines)
                cards.append(card)
                i += j  # Skip the lines we processed
        
        i += 1
    
    return cards

def extract_cc_inline_format(text):
    """Extract standalone CC numbers with nearby CVV/exp in same line or context."""
    cards = []
    
    # Find all card numbers first
    for match in CC_NUMBER_RE.finditer(text):
        card_num = clean_card_number(match.group())
        if not luhn_check(card_num):
            continue
        
        # Get surrounding context (200 chars before and after)
        start = max(0, match.start() - 200)
        end = min(len(text), match.end() + 200)
        context = text[start:end]
        
        card = {'number': card_num, 'format': 'inline', 'context': context[:500]}
        
        # Look for CVV nearby
        cvv_patterns = [
            re.compile(r'(?:cvv?|cvc|security|code)\s*[:=]?\s*(\d{3,4})', re.I),
            re.compile(r'\b(\d{3,4})\b'),  # Fallback: any 3-4 digit number
        ]
        
        for cvv_pattern in cvv_patterns:
            cvv_match = cvv_pattern.search(context[match.end()-start:])
            if cvv_match:
                potential_cvv = cvv_match.group(1) if cvv_match.lastindex else cvv_match.group()
                if re.match(r'^\d{3,4}$', potential_cvv):
                    card['cvv'] = potential_cvv
                    break
        
        # Look for expiration nearby
        exp_patterns = [
            re.compile(r'(?:exp|valid|fecha|venc)\w*\s*[:=]?\s*(\d{1,2}[/\-]\d{2,4})', re.I),
            re.compile(r'(\d{1,2}[/\-](20)?\d{2})\b'),
        ]
        
        for exp_pattern in exp_patterns:
            exp_match = exp_pattern.search(context)
            if exp_match:
                exp_str = exp_match.group(1)
                month, year = parse_expiration(exp_str)
                if month:
                    card['exp_month'] = month
                if year:
                    card['exp_year'] = year
                break
        
        cards.append(card)
    
    return cards

def extract_all_credit_cards(text, source_file=""):
    """Master function to extract credit cards using all methods."""
    all_cards = []
    seen_numbers = set()
    
    # Try all extraction methods
    methods = [
        ('labeled', extract_cc_labeled_format),
        ('delimited', extract_cc_delimited_format),
        ('newline', extract_cc_newline_format),
        ('inline', extract_cc_inline_format),
    ]
    
    for method_name, method_func in methods:
        try:
            cards = method_func(text)
            for card in cards:
                if card['number'] not in seen_numbers:
                    seen_numbers.add(card['number'])
                    card['source_file'] = source_file
                    card['card_type'] = get_card_type(card['number'])
                    all_cards.append(card)
        except Exception as e:
            pass  # Silently continue on errors
    
    return all_cards

def format_cc_full(card):
    """Format credit card for full info output."""
    lines = []
    lines.append(f"Card Number: {card['number']}")
    lines.append(f"Card Type: {card.get('card_type', 'unknown').upper()}")
    
    if card.get('name'):
        lines.append(f"Name: {card['name']}")
    
    exp = ""
    if card.get('exp_month') and card.get('exp_year'):
        exp = f"{card['exp_month']}/{card['exp_year']}"
    elif card.get('exp_year'):
        exp = card['exp_year']
    if exp:
        lines.append(f"Expiration: {exp}")
    
    if card.get('cvv'):
        lines.append(f"CVV: {card['cvv']}")
    
    lines.append(f"Format: {card.get('format', 'unknown')}")
    if card.get('source_file'):
        lines.append(f"Source: {card['source_file']}")
    
    return '\n'.join(lines)

def format_cc_standard(card):
    """Format credit card in standardized num|mm|yyyy|cvv format."""
    num = card['number']
    month = card.get('exp_month', '')
    year = card.get('exp_year', '')
    cvv = card.get('cvv', '')
    
    # Use N/A for missing values
    if not month or month == '00':
        month = 'N/A'
    if not year or year == '0000':
        year = 'N/A'
    if not cvv or cvv == '000':
        cvv = 'N/A'
    
    # Ensure year is 4 digits if present
    if year != 'N/A' and len(year) == 2:
        year = '20' + year
    
    return f"{num}|{month}|{year}|{cvv}"

def is_card_complete(card):
    """Check if card has all required info: number, month, year, CVV."""
    month = card.get('exp_month', '')
    year = card.get('exp_year', '')
    cvv = card.get('cvv', '')
    
    has_month = month and month != '00' and month != 'N/A'
    has_year = year and year != '0000' and year != 'N/A'
    has_cvv = cvv and cvv != '000' and cvv != 'N/A'
    
    return has_month and has_year and has_cvv

def save_cc_results(cards, output_dir="."):
    """Save credit card results to three files."""
    saved_files = []
    
    if not cards:
        return saved_files
    
    # Separate complete and incomplete cards
    complete_cards = [c for c in cards if is_card_complete(c)]
    incomplete_cards = [c for c in cards if not is_card_complete(c)]
    
    # FILE 1: Complete cards (has number, month, year, CVV)
    complete_path = os.path.join(output_dir, "cc_complete.txt")
    with open(complete_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("COMPLETE CREDIT CARDS (with CVV, Month, Year)\n")
        f.write(f"Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total: {len(complete_cards)} cards\n")
        f.write("=" * 70 + "\n")
        f.write("# Format: number|month|year|cvv\n\n")
        
        for card in complete_cards:
            num = card['number']
            month = card.get('exp_month', '').zfill(2)
            year = card.get('exp_year', '')
            if len(year) == 2:
                year = '20' + year
            cvv = card.get('cvv', '')
            f.write(f"{num}|{month}|{year}|{cvv}\n")
    
    saved_files.append(("CC_COMPLETE", complete_path, len(complete_cards)))
    
    # FILE 2: Incomplete cards (missing CVV, month, or year)
    incomplete_path = os.path.join(output_dir, "cc_incomplete.txt")
    with open(incomplete_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("INCOMPLETE CREDIT CARDS (missing CVV, Month, or Year)\n")
        f.write(f"Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total: {len(incomplete_cards)} cards\n")
        f.write("=" * 70 + "\n")
        f.write("# Format: number|month|year|cvv (N/A = not available)\n\n")
        
        for card in incomplete_cards:
            f.write(format_cc_standard(card) + "\n")
    
    saved_files.append(("CC_INCOMPLETE", incomplete_path, len(incomplete_cards)))
    
    # FILE 3: Full info file (all cards with details)
    full_path = os.path.join(output_dir, "cc_full_info.txt")
    with open(full_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("ALL CREDIT CARDS - FULL DETAILS\n")
        f.write(f"Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Cards: {len(cards)}\n")
        f.write(f"Complete: {len(complete_cards)} | Incomplete: {len(incomplete_cards)}\n")
        f.write("=" * 70 + "\n\n")
        
        for i, card in enumerate(cards, 1):
            status = "COMPLETE" if is_card_complete(card) else "INCOMPLETE"
            f.write(f"[CARD {i}] - {status}\n")
            f.write(format_cc_full(card))
            f.write("\n" + "-" * 40 + "\n\n")
    
    saved_files.append(("CC_FULL_INFO", full_path, len(cards)))
    
    return saved_files

def _extract_from_data(data, filename):
    """Helper to extract cards from raw data - used by parallel workers."""
    # Skip binary content
    if is_binary_content(data):
        return []
    
    # Try decoding with fast path
    text = None
    try:
        text = data.decode('utf-8', errors='ignore')
    except:
        try:
            text = data.decode('latin-1', errors='ignore')
        except:
            return []
    
    if not text or len(text) < 13:  # Minimum card number length
        return []
    
    return extract_all_credit_cards(text, filename)

def process_cc_extraction(path):
    """Process files for credit card extraction - FAST parallel version."""
    all_cards = []
    found_count = [0]  # Use list for mutable counter in nested function
    
    if os.path.isfile(path):
        print(f"\n  [*] Processing file: {path}")
        
        # Handle ZIP files
        if path.lower().endswith('.zip'):
            zip_password = None
            try:
                # Check if ZIP is encrypted
                if check_zip_encrypted(path):
                    print(f"  [!] ZIP file is password protected!")
                    user_pwd = input("  [?] Enter ZIP password (or press Enter to skip): ").strip()
                    if user_pwd:
                        try:
                            zip_password = user_pwd.encode('utf-8')
                            with zipfile.ZipFile(path, 'r') as zf:
                                for fi in zf.filelist:
                                    if not fi.is_dir():
                                        with zf.open(fi.filename, pwd=zip_password) as f:
                                            f.read(1)
                                        break
                            print(f"  [+] Password accepted!")
                        except:
                            print(f"  [!] Invalid password. Skipping encrypted files.")
                            zip_password = None
                    else:
                        print(f"  [!] No password provided. Skipping encrypted files.")
                
                with zipfile.ZipFile(path, 'r') as zf:
                    # Pre-filter files - skip binaries and huge files FAST
                    all_files = [f for f in zf.filelist if not f.is_dir()]
                    
                    # Separate nested zips and text files
                    nested_zips = []
                    text_files = []
                    skipped = 0
                    
                    for fi in all_files:
                        if fi.filename.lower().endswith('.zip'):
                            nested_zips.append(fi)
                        elif is_likely_text_file(fi.filename, fi.file_size):
                            text_files.append(fi)
                        else:
                            skipped += 1
                    
                    total = len(text_files)
                    print(f"  [ZIP] {total} text files, {len(nested_zips)} nested zips, {skipped} skipped")
                    
                    # Process nested zips first (sequentially to avoid memory issues)
                    for fi in nested_zips:
                        print(f"  [*] Found nested ZIP: {fi.filename}")
                        try:
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
                                with zf.open(fi.filename, pwd=zip_password) as f:
                                    tmp.write(f.read())
                                tmp_path = tmp.name
                            nested_cards = process_cc_extraction(tmp_path)
                            if nested_cards:
                                all_cards.extend(nested_cards)
                            os.unlink(tmp_path)
                        except Exception as e:
                            print(f"  [!] Error with nested ZIP: {e}")
                    
                    # Read all file data first (I/O bound)
                    print(f"  [*] Reading files...")
                    file_data = []
                    for fi in text_files:
                        try:
                            with zf.open(fi.filename, pwd=zip_password) as f:
                                data = f.read()
                                file_data.append((fi.filename, data))
                        except:
                            pass
                    
                    # Process in parallel (CPU bound)
                    print(f"  [*] Extracting cards (parallel)...")
                    
                    # Use ThreadPoolExecutor for parallel extraction - 200 THREADS
                    with ThreadPoolExecutor(max_workers=200) as executor:
                        futures = {
                            executor.submit(_extract_from_data, data, filename): filename 
                            for filename, data in file_data
                        }
                        
                        processed = 0
                        for future in as_completed(futures):
                            processed += 1
                            try:
                                cards = future.result()
                                if cards:
                                    all_cards.extend(cards)
                                    found_count[0] += len(cards)
                            except:
                                pass
                            
                            # Progress update every 500 files
                            if processed % 500 == 0 or processed == len(futures):
                                pct = int(processed / len(futures) * 100)
                                print(f"  [{pct:3d}%] {processed}/{len(futures)} | Found: {found_count[0]} cards")
                    
            except Exception as e:
                print(f"  [!] Error processing ZIP: {e}")
        
        # Handle RAR files
        elif path.lower().endswith('.rar'):
            print(f"  [RAR] Extracting archive...")
            rar_password = None
            
            # First try without password
            temp_dir, error = extract_rar_to_temp(path)
            
            if error == 'password_needed':
                print(f"  [!] RAR file is password protected!")
                user_pwd = input("  [?] Enter RAR password (or press Enter to skip): ").strip()
                if user_pwd:
                    temp_dir, error = extract_rar_to_temp(path, user_pwd)
                    if temp_dir:
                        print(f"  [+] Password accepted!")
                    else:
                        print(f"  [!] Invalid password or extraction error.")
                        return []
                else:
                    print(f"  [!] No password provided. Skipping.")
                    return []
            elif error:
                print(f"  [!] Error extracting RAR: {error}")
                return []
            
            if temp_dir:
                try:
                    print(f"  [*] Processing extracted files...")
                    nested_cards = process_cc_extraction(temp_dir)
                    if nested_cards:
                        all_cards.extend(nested_cards)
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)
        
        else:
            text = read_file(path)
            if text:
                cards = extract_all_credit_cards(text, path)
                all_cards.extend(cards)
                print(f"  [+] Found {len(cards)} credit cards")
    else:
        print(f"\n  [*] Processing folder: {path}")
        
        # Collect all files first
        file_list = []
        nested_zips = []
        
        nested_rars = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for filename in files:
                if filename.startswith('.'):
                    continue
                filepath = os.path.join(root, filename)
                if filepath.lower().endswith('.zip'):
                    nested_zips.append(filepath)
                elif filepath.lower().endswith('.rar'):
                    nested_rars.append(filepath)
                elif is_likely_text_file(filename):
                    file_list.append(filepath)
        
        print(f"  [*] Found {len(file_list)} text files, {len(nested_zips)} zip files, {len(nested_rars)} rar files")
        
        # Process nested zips
        for zp in nested_zips:
            nested_cards = process_cc_extraction(zp)
            if nested_cards:
                all_cards.extend(nested_cards)
        
        # Process nested rars
        for rp in nested_rars:
            nested_cards = process_cc_extraction(rp)
            if nested_cards:
                all_cards.extend(nested_cards)
        
        # Process text files in parallel
        if file_list:
            def process_file(filepath):
                try:
                    text = read_file(filepath)
                    if text:
                        return extract_all_credit_cards(text, filepath)
                except:
                    pass
                return []
            
            with ThreadPoolExecutor(max_workers=200) as executor:
                futures = {executor.submit(process_file, fp): fp for fp in file_list}
                processed = 0
                for future in as_completed(futures):
                    processed += 1
                    try:
                        cards = future.result()
                        if cards:
                            all_cards.extend(cards)
                    except:
                        pass
                    
                    if processed % 100 == 0:
                        print(f"  [{int(processed/len(file_list)*100):3d}%] {processed}/{len(file_list)}")
        
        print(f"  [*] Processed {len(file_list)} files")
    
    # Deduplicate by card number
    seen = set()
    unique_cards = []
    for card in all_cards:
        if card['number'] not in seen:
            seen.add(card['number'])
            unique_cards.append(card)
    
    return unique_cards

def extract_discord_tokens_fast(path, num_threads=200):
    """Extract Discord tokens using multi-threaded fast processing."""
    discord_tokens = []
    tokens_lock = threading.Lock()
    
    def scan_file(filepath):
        """Scan a single file for Discord tokens."""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                try:
                    text = content.decode('utf-8', errors='ignore')
                except:
                    return
                
                for match in DISCORD_TOKEN_RE.finditer(text):
                    token = match.group(0)
                    if token and len(token) > 20:
                        with tokens_lock:
                            if token not in discord_tokens:
                                discord_tokens.append(token)
        except:
            pass
    
    def scan_directory(dirpath):
        """Recursively scan directory with thread pool."""
        files_to_scan = []
        archives = []
        
        for root, dirs, files in os.walk(dirpath):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    if filepath.lower().endswith('.rar'):
                        archives.append(('rar', filepath))
                    elif filepath.lower().endswith('.zip'):
                        archives.append(('zip', filepath))
                    elif os.path.getsize(filepath) < 50 * 1024 * 1024:
                        files_to_scan.append(filepath)
                except:
                    pass
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            list(executor.map(scan_file, files_to_scan))
        
        # Process archives
        for atype, apath in archives:
            if atype == 'rar':
                temp_dir, error = extract_rar_to_temp(apath)
                if temp_dir and not error:
                    try:
                        scan_directory(temp_dir)
                    finally:
                        shutil.rmtree(temp_dir, ignore_errors=True)
            elif atype == 'zip':
                try:
                    with zipfile.ZipFile(apath, 'r') as zf:
                        with tempfile.TemporaryDirectory() as tmpdir:
                            zf.extractall(tmpdir)
                            scan_directory(tmpdir)
                except:
                    pass
    
    if os.path.isfile(path):
        if path.lower().endswith('.rar'):
            print(f"  [RAR] Extracting archive...")
            temp_dir, error = extract_rar_to_temp(path)
            if error == 'password_needed':
                print(f"  [!] RAR file is password protected!")
                user_pwd = input("  [?] Enter RAR password (or press Enter to skip): ").strip()
                if user_pwd:
                    temp_dir, error = extract_rar_to_temp(path, user_pwd)
                    if temp_dir:
                        print(f"  [+] Password accepted!")
            
            if temp_dir and not error:
                try:
                    scan_directory(temp_dir)
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)
            elif error:
                print(f"  [!] Error extracting RAR: {error}")
        elif path.lower().endswith('.zip'):
            print(f"  [ZIP] Extracting archive...")
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        zf.extractall(tmpdir)
                        scan_directory(tmpdir)
            except Exception as e:
                print(f"  [!] Error extracting ZIP: {e}")
        else:
            scan_file(path)
    else:
        scan_directory(path)
    
    return discord_tokens

def print_cc_analysis(cards):
    """Print analysis of extracted credit cards."""
    if not cards:
        return
    
    print("\n" + "=" * 70)
    print("                      CC ANALYSIS")
    print("=" * 70)
    
    # Card type breakdown
    type_counts = defaultdict(int)
    for card in cards:
        type_counts[card.get('card_type', 'unknown')] += 1
    
    print(f"\n  CARD TYPE BREAKDOWN:")
    for ctype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        bar = "#" * min(count, 30)
        print(f"    [{ctype.upper():12s}] {count:4d} {bar}")
    
    # Completeness analysis
    complete = sum(1 for c in cards if all(k in c for k in ['exp_month', 'exp_year', 'cvv']))
    partial = len(cards) - complete
    
    print(f"\n  COMPLETENESS:")
    print(f"    Complete (with exp+cvv): {complete}")
    print(f"    Partial (missing data):  {partial}")
    
    # Format breakdown
    format_counts = defaultdict(int)
    for card in cards:
        format_counts[card.get('format', 'unknown')] += 1
    
    print(f"\n  FORMAT DETECTED:")
    for fmt, count in sorted(format_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    [{fmt:12s}] {count:4d}")
    
    # Preview
    preview_count = min(10, len(cards))
    print(f"\n  PREVIEW (first {preview_count}):")
    print("  " + "-" * 65)
    for card in cards[:preview_count]:
        ctype = card.get('card_type', '?')[:6].upper()
        num = card['number']
        masked = num[:4] + '*' * (len(num) - 8) + num[-4:]
        exp = f"{card.get('exp_month', '??')}/{card.get('exp_year', '????')}"
        cvv = card.get('cvv', '???')
        print(f"    [{ctype:6s}] {masked} | {exp} | CVV:{cvv}")

def save_results(creds, output_dir, mode, target_sites=None, target_categories=None, target_domains=None):
    """Save results to files."""
    os.makedirs(output_dir, exist_ok=True)
    saved_files = []
    
    if mode == "domain" and target_domains:
        all_filepath = os.path.join(output_dir, "domain_combos.txt")
        seen = set()
        with open(all_filepath, 'w', encoding='utf-8') as f:
            for cred in creds:
                key = f"{cred['username'].lower()}:{cred['password']}"
                if key not in seen:
                    seen.add(key)
                    f.write(f"{cred['username']}:{cred['password']}\n")
        saved_files.append(("DOMAIN", all_filepath, len(seen)))
        return saved_files
    
    if mode == "targeted" and target_sites:
        site_creds = defaultdict(list)
        
        for cred in creds:
            site = cred.get('site', 'unknown')
            if site:
                site_creds[site].append(cred)
        
        for site, site_cred_list in site_creds.items():
            if site_cred_list:
                filename = f"{site}_combos.txt"
                filepath = os.path.join(output_dir, filename)
                seen = set()
                with open(filepath, 'w', encoding='utf-8') as f:
                    for cred in site_cred_list:
                        key = f"{cred['username'].lower()}:{cred['password']}"
                        if key not in seen:
                            seen.add(key)
                            f.write(f"{cred['username']}:{cred['password']}\n")
                saved_files.append((site, filepath, len(seen)))
        
        all_filepath = os.path.join(output_dir, "all_targeted_combos.txt")
        seen = set()
        with open(all_filepath, 'w', encoding='utf-8') as f:
            for cred in creds:
                key = f"{cred['username'].lower()}:{cred['password']}"
                if key not in seen:
                    seen.add(key)
                    f.write(f"{cred['username']}:{cred['password']}\n")
        saved_files.append(("ALL TARGETED", all_filepath, len(seen)))
    else:
        all_filepath = os.path.join(output_dir, "all_combos.txt")
        seen = set()
        with open(all_filepath, 'w', encoding='utf-8') as f:
            for cred in creds:
                key = f"{cred['username'].lower()}:{cred['password']}"
                if key not in seen:
                    seen.add(key)
                    f.write(f"{cred['username']}:{cred['password']}\n")
        saved_files.append(("ALL", all_filepath, len(seen)))
    
    json_filepath = os.path.join(output_dir, "results_detailed.json")
    with open(json_filepath, 'w', encoding='utf-8') as f:
        json_data = []
        for cred in creds:
            json_data.append({
                'username': cred['username'],
                'password': cred['password'],
                'url': cred.get('url'),
                'site': cred.get('site'),
                'category': cred.get('category'),
                'password_strength': cred.get('strength', {}).get('strength', 'UNKNOWN')
            })
        json.dump(json_data, f, indent=2)
    saved_files.append(("JSON", json_filepath, len(json_data)))
    
    return saved_files

def show_menu():
    """Display extraction mode menu."""
    print("\n  " + "-" * 60)
    print("  SELECT EXTRACTION MODE:")
    print("  " + "-" * 60)
    print("  [1] TARGETED    - Extract from specific websites/apps only")
    print("  [2] EXTRACT ALL - Extract everything into one combo file")
    print("  [3] EMAIL DOMAIN- Extract by email domain (edu, gmail...)")
    print("  [4] CREDIT CARDS- Extract CC info (all formats supported)")
    print("  [5] DISCORD    - Extract Discord tokens (fast multi-threaded)")
    print("  " + "-" * 60)

def show_categories():
    """Display available categories."""
    print("\n  " + "-" * 60)
    print("  AVAILABLE CATEGORIES:")
    print("  " + "-" * 60)
    for cat, sites in SITE_CATEGORIES.items():
        sample = ', '.join(sites[:5])
        if len(sites) > 5:
            sample += f"... (+{len(sites)-5} more)"
        print(f"  [{cat.upper():12s}] {sample}")
    print("  " + "-" * 60)

def get_targets():
    """Get target sites from user."""
    print("\n  " + "-" * 60)
    print("  ADVANCED TARGETED EXTRACTION MODE")
    print("  " + "-" * 60)
    print("  Search for ANY website, app, or keyword!")
    print("  Works with ANY text - not just predefined sites")
    print("")
    print("  EXAMPLES:")
    print("    netflix spotify disney hulu amazon crunchyroll")
    print("    instagram facebook twitter tiktok snapchat")
    print("    steam epic fortnite valorant roblox minecraft")
    print("    paypal coinbase binance cashapp")
    print("    dragonbound tioanime launcherfenix (any custom site!)")
    print("")
    print("  ADVANCED SEARCH:")
    print("    - Type ANY part of URL/domain to find it")
    print("    - Works with Android app names (com.app.name)")
    print("    - Searches usernames too!")
    print("")
    print(f"  KNOWN SITES: {len(POPULAR_SITES)} + unlimited custom searches")
    print("  " + "-" * 60)
    
    user_input = input("\n  [?] Enter targets: ").strip()
    targets = parse_target_sites(user_input)
    
    if not targets:
        print("  [!] No valid targets found. Please try again.")
        return None
    
    print(f"  [+] Targeting {len(targets)} sites: {', '.join(sorted(targets)[:10])}")
    if len(targets) > 10:
        print(f"      ... and {len(targets) - 10} more")
    confirm = input("  [?] Confirm? (y/n): ").strip().lower()
    
    if confirm != 'y':
        return None
    
    return targets

def get_email_domains():
    """Get target email domains from user."""
    print("\n  " + "-" * 60)
    print("  ADVANCED EMAIL DOMAIN EXTRACTION MODE")
    print("  " + "-" * 60)
    print("  Extract emails & passwords by domain")
    print("")
    print("  EXAMPLES:")
    print("    gmail hotmail outlook yahoo")
    print("    edu (ALL educational emails: .edu, .edu.pe, .edu.mx, etc)")
    print("    gov (ALL government emails)")
    print("    protonmail icloud aol")
    print("    gmail edu outlook")
    print("    university school (educational keywords)")
    print("")
    print("  SMART KEYWORDS:")
    print("    edu       - Finds ALL .edu emails worldwide")
    print("    gov       - Finds ALL .gov emails")
    print("    university - Finds edu, uni, university, college domains")
    print("    school    - Finds edu, school, k12 domains")
    print("")
    print("  POPULAR DOMAINS: gmail, hotmail, outlook, yahoo, edu,")
    print("    protonmail, icloud, aol, live, msn, yandex, mail,")
    print("    gmx, zoho, tutanota, fastmail")
    print("  " + "-" * 60)
    
    user_input = input("\n  [?] Enter domains: ").strip()
    domains, wildcard_patterns = parse_email_domains(user_input)
    
    if not domains and not wildcard_patterns:
        print("  [!] No valid domains found. Please try again.")
        return None, None
    
    all_targets = list(domains) + [f"pattern:{p}" for p in wildcard_patterns]
    print(f"  [+] Targeting {len(all_targets)} filters:")
    if domains:
        print(f"      Exact domains: {', '.join(sorted(domains))}")
    if wildcard_patterns:
        print(f"      Smart patterns: {', '.join(sorted(wildcard_patterns))}")
    confirm = input("  [?] Confirm? (y/n): ").strip().lower()
    
    if confirm != 'y':
        return None, None
    
    return domains, wildcard_patterns

def parse_email_domains(user_input):
    """Parse user input for email domains."""
    user_input = user_input.lower().strip()
    user_input = re.sub(r'[,;|:]', ' ', user_input)
    
    parts = user_input.split()
    domains = set()
    
    domain_aliases = {
        'gmail': ['gmail.com', 'googlemail.com'],
        'hotmail': ['hotmail.com', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.de', 'hotmail.es'],
        'outlook': ['outlook.com', 'outlook.es', 'outlook.fr', 'outlook.de', 'outlook.co.uk'],
        'yahoo': ['yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'yahoo.es', 'yahoo.com.br'],
        'live': ['live.com', 'live.co.uk', 'live.fr', 'live.de'],
        'msn': ['msn.com'],
        'aol': ['aol.com', 'aol.co.uk'],
        'icloud': ['icloud.com', 'me.com', 'mac.com'],
        'protonmail': ['protonmail.com', 'proton.me', 'pm.me'],
        'yandex': ['yandex.com', 'yandex.ru', 'ya.ru'],
        'mail': ['mail.com', 'mail.ru'],
        'gmx': ['gmx.com', 'gmx.de', 'gmx.net'],
        'zoho': ['zoho.com', 'zohomail.com'],
        'tutanota': ['tutanota.com', 'tutamail.com'],
        'fastmail': ['fastmail.com', 'fastmail.fm'],
        'edu': ['*edu*'],
        'gov': ['*gov*'],
        'mil': ['*mil*'],
        'ac.uk': ['.ac.uk'],
        'edu.co': ['.edu.co'],
        'edu.mx': ['.edu.mx'],
        'edu.br': ['.edu.br'],
        'edu.ar': ['.edu.ar'],
        'edu.pe': ['.edu.pe'],
        'university': ['*edu*', '*uni*', '*university*', '*college*', '*ac.*'],
        'school': ['*edu*', '*school*', '*k12*', '*ac.*'],
    }
    
    wildcard_patterns = set()
    
    for part in parts:
        part = part.strip().replace('@', '')
        if not part:
            continue
        
        if part in domain_aliases:
            for alias in domain_aliases[part]:
                if alias.startswith('*') or alias.endswith('*'):
                    wildcard_patterns.add(alias)
                else:
                    domains.add(alias)
        else:
            if not part.startswith('.'):
                if '.' not in part:
                    part = f".{part}"
                else:
                    part = part if part.startswith('.') else part
            domains.add(part)
    
    return domains, wildcard_patterns

def filter_by_email_domain(creds, target_domains, wildcard_patterns=None):
    """Filter credentials to only include emails matching target domains.
    
    Advanced filtering with wildcard support:
    - Exact domain matching (gmail.com)
    - Suffix matching (.edu.pe)
    - Wildcard patterns (*edu* matches any domain containing 'edu')
    """
    if not target_domains and not wildcard_patterns:
        return creds
    
    if wildcard_patterns is None:
        wildcard_patterns = set()
    
    filtered = []
    for cred in creds:
        username = cred.get('username', '').lower()
        if '@' in username:
            email_domain = username.split('@')[1]
            matched = False
            
            for pattern in wildcard_patterns:
                clean_pattern = pattern.replace('*', '')
                if clean_pattern in email_domain:
                    matched = True
                    break
            
            if not matched:
                for target in target_domains:
                    if target.startswith('.'):
                        if email_domain.endswith(target) or email_domain.endswith(target[1:]):
                            matched = True
                            break
                    else:
                        if email_domain == target or email_domain.endswith(f".{target}"):
                            matched = True
                            break
            
            if matched:
                filtered.append(cred)
    
    return filtered

def get_categories():
    """Get target categories from user."""
    show_categories()
    
    user_input = input("\n  [?] Enter categories: ").strip()
    categories = parse_target_categories(user_input)
    
    if not categories:
        print("  [!] No valid categories found. Please try again.")
        return None
    
    print(f"  [+] Targeting categories: {', '.join(sorted(categories))}")
    confirm = input("  [?] Confirm? (y/n): ").strip().lower()
    
    if confirm != 'y':
        return None
    
    return categories

def get_cred_type(username):
    """Determine credential type."""
    if EMAIL_RE.match(username):
        return "EMAIL"
    clean = username.replace(' ', '').replace('-', '').replace('+', '').replace('(', '').replace(')', '')
    if clean.isdigit() and len(clean) >= 7:
        return "PHONE"
    return "USER"

def print_analysis(all_creds):
    """Print detailed analysis of extracted credentials."""
    print("\n" + "=" * 70)
    print("                       DETAILED ANALYSIS")
    print("=" * 70)
    
    category_counts = defaultdict(int)
    strength_counts = defaultdict(int)
    site_counts = defaultdict(int)
    
    for cred in all_creds:
        category_counts[cred.get('category', 'unknown')] += 1
        strength_counts[cred.get('strength', {}).get('strength', 'UNKNOWN')] += 1
        site_counts[cred.get('site', 'unknown')] += 1
    
    print(f"\n  CATEGORY BREAKDOWN:")
    for cat in sorted(category_counts.keys()):
        count = category_counts[cat]
        bar = "#" * min(count, 30)
        print(f"    [{cat.upper():12s}] {count:4d} {bar}")
    
    print(f"\n  PASSWORD STRENGTH:")
    strength_order = ['STRONG', 'MEDIUM', 'WEAK', 'VERY WEAK', 'UNKNOWN']
    for strength in strength_order:
        if strength in strength_counts:
            count = strength_counts[strength]
            bar = "#" * min(count, 30)
            print(f"    [{strength:10s}] {count:4d} {bar}")
    
    print(f"\n  TOP 15 SITES:")
    sorted_sites = sorted(site_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    for site, count in sorted_sites:
        if site and site != 'unknown':
            bar = "#" * min(count, 25)
            print(f"    [{site[:14]:14s}] {count:4d} {bar}")
    
    reused = detect_password_reuse(all_creds)
    if reused:
        print(f"\n  PASSWORD REUSE DETECTED: {len(reused)} passwords used multiple times")
        reused_sorted = sorted(reused.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        for pw, accounts in reused_sorted:
            masked_pw = pw[:3] + '*' * (len(pw) - 6) + pw[-3:] if len(pw) > 6 else '***'
            print(f"    [{masked_pw}] used by {len(accounts)} accounts")

def main():
    print_banner()
    
    path = input("  [?] Path to file/folder: ").strip()
    
    if not path:
        print("  [!] No path provided.")
        return
    
    if not os.path.exists(path):
        print(f"  [!] Path not found: {path}")
        return
    
    show_menu()
    choice = input("\n  [?] Enter choice (1-5): ").strip()
    
    target_sites = None
    target_categories = None
    target_domains = None
    wildcard_patterns = None
    mode = "all"
    
    if choice == "1":
        target_sites = get_targets()
        if not target_sites:
            print("  [!] Cancelled.")
            return
        mode = "targeted"
        print(f"\n  [*] TARGETED MODE - Extracting from: {', '.join(sorted(list(target_sites)[:5]))}")
        if len(target_sites) > 5:
            print(f"      ... and {len(target_sites) - 5} more sites")
    elif choice == "3":
        target_domains, wildcard_patterns = get_email_domains()
        if not target_domains and not wildcard_patterns:
            print("  [!] Cancelled.")
            return
        mode = "domain"
        all_filters = list(target_domains or []) + list(wildcard_patterns or [])
        print(f"\n  [*] ADVANCED EMAIL DOMAIN MODE - {len(all_filters)} filters active")
        if target_domains:
            print(f"      Exact domains: {', '.join(sorted(list(target_domains)[:3]))}")
        if wildcard_patterns:
            print(f"      Smart patterns: {', '.join(sorted(list(wildcard_patterns)[:3]))}")
    elif choice == "4":
        # Credit Card Extraction Mode
        print("\n" + "=" * 70)
        print("                   CREDIT CARD EXTRACTION MODE")
        print("=" * 70)
        print("\n  [*] Supported formats:")
        print("      - Labeled:   CardNumber: XXXX, CVC: XXX, Exp: MM/YYYY")
        print("      - Pipe:      4854422144891954|11|2028|415")
        print("      - Slash:     4854422144891954/11/2028/415")
        print("      - Newline:   Card number on separate lines")
        print("      - Inline:    Card numbers with nearby exp/cvv")
        print("\n  [*] Card types: Visa, Mastercard, Amex, Discover, Diners, JCB")
        print("  [*] Validates using Luhn algorithm")
        
        start_time = datetime.now()
        cards = process_cc_extraction(path)
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if cards:
            saved_files = save_cc_results(cards)
            
            print("\n" + "=" * 70)
            print("                      CC EXTRACTION RESULTS")
            print("=" * 70)
            print(f"\n  TIME ELAPSED:    {elapsed:.1f} seconds")
            print(f"  CARDS FOUND:     {len(cards)}")
            
            # Count by type
            type_counts = defaultdict(int)
            for card in cards:
                type_counts[card.get('card_type', 'unknown')] += 1
            
            print(f"\n  BY CARD TYPE:")
            for ctype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"    [{ctype.upper():12s}] {count}")
            
            complete = sum(1 for c in cards if all(k in c for k in ['exp_month', 'exp_year', 'cvv']))
            print(f"\n  COMPLETE CARDS:  {complete} (with exp + cvv)")
            print(f"  PARTIAL CARDS:   {len(cards) - complete} (missing some data)")
            
            print(f"\n  OUTPUT FILES:")
            for label, filepath, count in saved_files:
                print(f"    [{label:12s}] {os.path.basename(filepath)} ({count} entries)")
            
            print_cc_analysis(cards)
        else:
            print("\n  [!] No credit cards found in the provided files.")
        
        print("\n" + "=" * 70)
        print("                          COMPLETE!")
        print("=" * 70 + "\n")
        return
    elif choice == "5":
        # Discord Token Extraction Mode
        print("\n" + "=" * 70)
        print("                   DISCORD TOKEN EXTRACTION MODE")
        print("=" * 70)
        print("\n  [*] Fast multi-threaded token extraction")
        print("  [*] Using 200 threads for maximum speed")
        print("  [*] Scanning for Discord bot & user tokens...")
        
        start_time = datetime.now()
        tokens = extract_discord_tokens_fast(path, num_threads=200)
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if tokens:
            output_file = "discord_tokens.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                for token in sorted(set(tokens)):
                    f.write(f"{token}\n")
            
            print("\n" + "=" * 70)
            print("                   DISCORD TOKEN RESULTS")
            print("=" * 70)
            print(f"\n  TIME ELAPSED:    {elapsed:.1f} seconds")
            print(f"  TOKENS FOUND:    {len(set(tokens))}")
            print(f"\n  OUTPUT FILES:")
            print(f"    [TOKENS     ] {output_file} ({len(set(tokens))} entries)")
        else:
            print("\n  [!] No Discord tokens found in the provided files.")
        
        print("\n" + "=" * 70)
        print("                          COMPLETE!")
        print("=" * 70 + "\n")
        return
    else:
        mode = "all"
        print("\n  [*] EXTRACTING ALL - Output: all_combos.txt")
    
    print(f"  [*] Processing: {path}")
    start_time = datetime.now()
    
    all_creds = []
    
    if os.path.isfile(path):
        if path.endswith('.zip'):
            print("\n  [TYPE] ZIP Archive")
            process_zip(path, all_creds, target_sites, target_categories)
        elif path.endswith('.db') or path.endswith('.sqlite'):
            print("\n  [TYPE] SQLite Database")
            creds = extract_sqlite_credentials(path, target_sites, target_categories)
            all_creds.extend(creds)
            print(f"  [+] Found: {len(all_creds)} credentials")
        else:
            print("\n  [TYPE] Single File")
            text = read_file(path)
            if text:
                creds = process_text(text, path, target_sites, target_categories)
                all_creds.extend(creds)
                print(f"  [+] Found: {len(all_creds)} credentials")
    else:
        print("\n  [TYPE] Folder")
        process_folder(path, all_creds, target_sites, target_categories)
    
    all_creds = deduplicate_creds(all_creds)
    
    if mode == "domain" and (target_domains or wildcard_patterns):
        all_creds = filter_by_email_domain(all_creds, target_domains or set(), wildcard_patterns)
        print(f"  [+] After advanced domain filter: {len(all_creds)} credentials")
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    output_dir = "."
    saved_files = save_results(all_creds, output_dir, mode, target_sites, target_categories, target_domains)
    
    email_count = sum(1 for c in all_creds if EMAIL_RE.match(c['username']))
    phone_count = sum(1 for c in all_creds if c['username'].replace(' ', '').replace('-', '').replace('+', '').replace('(', '').replace(')', '').isdigit())
    user_count = len(all_creds) - email_count - phone_count
    
    print("\n" + "=" * 70)
    print("                          RESULTS")
    print("=" * 70)
    
    if mode == "targeted" and target_sites:
        print(f"\n  MODE:            TARGETED ({len(target_sites)} sites)")
        print(f"  TARGETS:         {', '.join(sorted(list(target_sites)[:5]))}")
        if len(target_sites) > 5:
            print(f"                   ... and {len(target_sites) - 5} more")
    elif mode == "domain" and (target_domains or wildcard_patterns):
        all_filters = list(target_domains or []) + list(wildcard_patterns or [])
        print(f"\n  MODE:            ADVANCED EMAIL DOMAIN ({len(all_filters)} filters)")
        if target_domains:
            print(f"  EXACT DOMAINS:   {', '.join(sorted(list(target_domains)[:5]))}")
        if wildcard_patterns:
            print(f"  SMART PATTERNS:  {', '.join(sorted(list(wildcard_patterns)[:5]))}")
    else:
        print(f"\n  MODE:            FULL EXTRACTION")
    
    print(f"  TIME ELAPSED:    {elapsed:.1f} seconds")
    
    print(f"\n  CREDENTIALS FOUND:")
    print(f"    Total:         {len(all_creds)}")
    print(f"    Emails:        {email_count}")
    print(f"    Usernames:     {user_count}")
    print(f"    Phones:        {phone_count}")
    
    print(f"\n  OUTPUT FILES:")
    for site, filepath, count in saved_files:
        print(f"    [{site.upper():12s}] {os.path.basename(filepath)} ({count} entries)")
    
    if all_creds:
        print_analysis(all_creds)
        
        preview_count = min(15, len(all_creds))
        print(f"\n  PREVIEW (first {preview_count}):")
        print("  " + "-" * 65)
        for i, cred in enumerate(all_creds[:preview_count]):
            ctype = get_cred_type(cred['username'])
            site = cred.get('site', '?')
            if site:
                site = site[:10]
            else:
                site = '?'
            strength = cred.get('strength', {}).get('strength', '?')[:6]
            username_display = cred['username'][:28]
            print(f"    [{ctype:5s}] [{site:10s}] [{strength:6s}] {username_display}")
    
    print("\n" + "=" * 70)
    print("                          COMPLETE!")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()
