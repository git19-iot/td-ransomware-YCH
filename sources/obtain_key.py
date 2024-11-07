
from xorcrypt import xorcrypt

# Définition du texte en clair et de la clé
texte_clair = b"JesusIsKing"
cle = b"clefsecrete"

# Affichage du texte en clair et de la clé
print(f"""
TEXTE EN CLAIR :\t {texte_clair}
CLE :\t\t {cle}
""")

# Chiffrement du texte en clair avec la clé
texte_chiffre = xorcrypt(texte_clair, cle)
print("TEXTE EN CLAIR xor CLE")
print("TEXTE CHIFFRE :\t", texte_chiffre)

# Déchiffrement du texte chiffré avec la clé
texte_dechiffre = xorcrypt(texte_chiffre, cle)
print("\nTEXTE CHIFFRE xor CLE")
print("TEXTE DECHIFFRE :\t", texte_dechiffre)

# Récupération de la clé en effectuant un XOR entre le texte en clair et le texte chiffré
cle_recuperee = xorcrypt(texte_clair, texte_chiffre)
print("\nTEXTE EN CLAIR xor TEXTE CHIFFRE")
print("CLE RECUPEREE :\t", cle_recuperee)

# Illustration de la faiblesse du chiffrement XOR avec un texte répétitif
texte_repetitif = b"mot_mot_mot_mot_mot_mot_"
texte_chiffre_repetitif = xorcrypt(texte_repetitif, cle)

print(f"""
--------------------------------------------------
TEXTE REPETITIF :\t {texte_repetitif}
TEXTE CHIFFRE :\t {texte_chiffre_repetitif}
--------------------------------------------------
""")

print("""
Si des mots se répètent dans le fichier, on peut observer des motifs répétitifs 
dans le texte chiffré, ce qui facilite la cryptanalyse.
""")