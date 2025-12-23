# Mapeo de Alias -> Nombre del archivo en data/wordlists
# Actualizado según la estructura del repo 'hackingyseguridad'

WORDLIST_MAP = {
    # --- Web Fuzzing ---
    "LFI_VARIATIONS": "pathtraversal.txt",  # Para LFI
    "XSS_REFLECTED": "xss.txt",  # Para XSS
    "SQLI_GENERIC": "claves2.txt",  # (Placeholder) Usaremos este mientras no haya uno específico de SQLi
    # --- Discovery ---
    "DIR_COMMON": "directorios.txt",  # Para buscar carpetas
    "SUBDOMAINS_TOP": "subdominios.txt",  # Para subdominios
    "FILES_COMMON": "ficheros.txt",  # Para buscar archivos
    # --- Credentials ---
    "USER_TOP": "usuarios.txt",  # Lista de usuarios
    "PASS_TOP": "claves.txt",  # Lista de contraseñas
    "SSH_DEFAULT": "clavescisco.txt",  # (Placeholder) Para pruebas SSH
}
