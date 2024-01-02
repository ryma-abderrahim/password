import hashlib
import json

def valide_password(password):
    #le mot de passe doit contenir au moins huit caractères.
    if len(password) < 8:
        return False
    
    #le mot de passe doit contenir au moins un chiffre
    elif  not any(char.isdigit() for char in password):
        return False
    
    #le mot de passe doit au moins contenir une lettre minuscule
    elif not any(char.islower() for char in password):
        return False
    
    #le mot de passe doit au moins contenir une lettre majuscule
    elif not any(char.isupper() for char in password):
        return False
    
    #le mot de passe doit au moins contenir un caractère spécial
    elif not any(not char.isalnum() for char in password):
        return False

    #toute les conditions sont valider 
    else:
        return True
    

#fonction de hachage 
def sha256_hash(password):
    hash= hashlib.sha256(password.encode())
    return hash.hexdigest()


#foction de stockage des mots de passe dans un fichier JSON
def add_passwords(password, username,file_name):
    #charger le contenue de fichier json
    with open(file_name, "r") as file :
        passwords=json.load(file)

    #Ajouter le nouveau mot de passe 
    passwords[username]=password

    #Sauvgarder les modifications dans le fichier json 
    with open(file_name, "w") as file:
        json.dump(passwords, file)



# Fonction pour afficher les mots de passe
def show_passwords(file_name):
    # Charger le contenu du fichier json
    with open(file_name, 'r') as file:
        passwords = json.load(file)
    
    # Afficher les mots de passe hachés
    for username, hashed_password in passwords.items():
        print(f"{username}: {hashed_password}")




#initialisation de fichier json vide
with open('passwords.json', 'w') as file:
    json.dump({}, file)


#initialisation de mot de passe
repeat=True
while repeat :
    user=input("Veuillez entrer un nom d'utilisateur:  ")
    
    #repeter la saisie de mot de passe jusqu'à qu'il soit valide 
    valide=False
    while valide==False :
        mot_de_passe = input("Veuillez entrer votre mot de passe : ")
        if valide_password(mot_de_passe):
            print("Mot de passe valide")
            valide=True
            hash_password=sha256_hash(mot_de_passe)
            add_passwords(hash_password,user,'passwords.json')
            print("Mot de passe hashé (SHA-256) : ",hash_password)


        else:
            print("Le mot de passe est incorrecte; le mot de passe doit contenir au mois 8 caractère : un chiffre ,une  lettre majuscule , une minuscule et un carctère spécial   ")
            Valide=False

    
    #Menu
    choice=input("[O] Pour ajouter un nouveau mot de passe\n[H] Pour afficher l'historique des mots de passe\n[Q] Pour arreter :  ")
    repeat=False
            
    #Entrer d'un autre mot de passe 
    if choice=='O':
        repeat=True
            
    #affichage de l'historique des mot de passe haché
    elif choice=='H':
        show_passwords('passwords.json')
        choice=input("[O] Pour ajouter un nouveau mot de passe\n[H] Pour afficher l'historique des mots de passe\n[Q] Pour arreter :  ")

    #quiter 
    elif choice=='Q':
         break      
    
    else:
        print("\n\tChoix incorrect \n")
        choice=input("[O] Pour ajouter un nouveau mot de passe\n[H] Pour afficher l'historique des mots de passe\n[Q] Pour arreter :  ")


