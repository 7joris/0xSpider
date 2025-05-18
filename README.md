# 0xSpider - Ultimate OSINT Tool  V1.0

![0xSpider Screenshot](https://cdn.discordapp.com/attachments/1372323802096336898/1373458314003742841/45d9342e-72e6-4a42-a895-80b579e67d47.png?ex=682a7c3b&is=68292abb&hm=ce0f4f713aa5745cab4edf662650d6193a9606a5888e9c1a9d4880066313659c&)

## Description

0xSpider est un outil OSINT complet conçu pour les enquêtes numériques et la collecte d'informations. Cet outil offre une large gamme de fonctionnalités pour analyser des domaines, adresses IP, emails, noms d'utilisateur, cryptomonnaies et bien plus encore.

## Fonctionnalités

### Investigations de base
- **Domaines** : WHOIS, DNS, sous-domaines, SSL
- **IP** : Géolocalisation, reverse DNS, scan de ports
- **Emails** : Fuites de données, WHOIS du domaine, réseaux sociaux
- **Téléphones** : Opérateur, géolocalisation
- **Noms d'utilisateur** : Recherche cross-platform

### Analyse avancée
- **Sites web** : Headers, liens, technologies
- **Images** : Métadonnées EXIF, hashs, recherche inversée
- **Fichiers** : Métadonnées, hashs, strings
- **Cryptomonnaies** : BTC, ETH, LTC - visualisation des transactions

### Outils spéciaux
- **Shodan** : Intégration avec l'API Shodan
- **Réseaux sociaux** : Analyse de graphes sociaux
- **Dark Web** : Monitoring simulé
- **Screenshots** : Capture de sites web
- **Analyse de données** : Visualisation géo, analyse textuelle

## Prérequis

- Python 3.8+
- Packages requis : pip install tkinter requests beautifulsoup4 python-whois dnspython pillow exifread phonenumbers ipwhois tldextract selenium networkx matplotlib textblob pandas numpy
- ChromeDriver pour la fonction screenshot (à configurer dans les paramètres)

## Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/7joris/0xSpider.git
```
```bash
cd 0xSpider
```
2. Installez les dépendances :
```bash
pip install -r requirements.txt
```
3. Lancez l'application :
```bash
python main.py
```

## Configuration

### Configurez vos clés API dans l'onglet Settings :
- Clé API Shodan (pour les fonctionnalités Shodan)
- Chemin vers ChromeDriver (pour les captures d'écran)

## Captures d'écran
![0xSpider Screenshot1](https://cdn.discordapp.com/attachments/1372323802096336898/1373452452942188604/image.png?ex=682a76c6&is=68292546&hm=baafbf01be6a325e516650d0493f05fea069fae619cbf5212b6c923acbe9487e&)
![0xSpider Screenshot1](https://cdn.discordapp.com/attachments/1372323802096336898/1373452646509449266/image.png?ex=682a76f4&is=68292574&hm=c55c4a41223f2ffd52e4529757ae421cac6fa588626efb63dc6b76ef08aba57e&)
![0xSpider Screenshot1](https://cdn.discordapp.com/attachments/1372323802096336898/1373452796455555093/image.png?ex=682a7718&is=68292598&hm=11b6729634885daba3799289440b45982839c787fd2c5ca09d397fd4b4e9b9f4&)
