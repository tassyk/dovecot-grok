# Logstash Grok patterns pour Dovecot 

Dovecot est un service de messagerie.

## Description
Dans ce dépôt, nous proposons des patterns Grok pour parser (structurer) les logs de Dovecot via Logstash:
- `dovecot.grok` : contient les patterns Grok
- `dovecot-logtash-pipeline.example` : est un fichier d'exemple de pipeline logstash montrant une méthode d'utilisation de ces patterns via Logtash.
- `dovecot-sample.log` : contient des exemples de log de Dovecot qui ont été testés.

## Remarque
- L'utilisation de ce dépôt nécessite la compréhension du fonctionnement de Logstash.
- Dans `dovecot-logtash-pipeline.example`, le répertoire du pattern doit être adapté.

## Help
- Construction des patterns à l'aide du site [Grok Constructor](https://grokconstructor.appspot.com/do/match)
- Doc Sun Oracle Messaging accessible [ici](https://docs.oracle.com/cd/E63708_01/doc.801/e63711/toc.htm)
