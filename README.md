# Analyseur réseau

# Projet - Transport et Services Réseau #


Après avoir effectué la commande make, le programme peut être lancé comme ci- dessous :
	
	Capture en ligne : 
	./bin/analyse -i <interface> -v <1..3> 

	Depuis un fichier : 
	./bin/analyse -o <fichier_capture> -v <1..3> 

	Application d’un filtre : 
	./bin/analyse -i <interface> -v <1..3> -f ‘src port 80’

Plusieurs captures sont fournis dans le dossier src/traces/ afin de pouvoir faire des tests.

Les protocoles disponibles sont : Ethernet, IP, TCP, UDP, HTTP, TELNET, ARP, BOOTP/DHCP, FTP, IMAP, SMTP, POP.

Trois types d’affichage sont possibles
        − très concis : une ligne par trame ( -v 1 )
        
	![alt text](https://image.noelshack.com/fichiers/2018/01/6/1515227491-concis.png)

        − synthétique : une ligne par protocole, soit quelques lignes par trame  ( -v 2 )
        
	![alt text](https://image.noelshack.com/fichiers/2018/01/6/1515227491-v2.png)

        − complet : la totalité des champs protocolaires et des contenus applicatifs  ( -v 3 )
        
	![alt text](https://image.noelshack.com/fichiers/2018/01/6/1515227491-full.png)



