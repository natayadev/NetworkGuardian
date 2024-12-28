# NetworkGuardian

🛡️ Bot de Telegram que analiza la red en búsqueda de dispositivos conectados no confiables, diseñado para ejecutarse en una Raspberry Pi 5 con soporte para Portainer.

## Requisitos

- Python 3.x
- Docker

---

## Instalación

*Aclaración: si bien este proyecto se ejecuta localmente en una RPi5 con Portainer, la imagen puede utilizarse en cualquier entorno.*

1. Clona el repositorio:

  ```bash
  git clone https://github.com/natayadev/networkguardian.git
  cd networkguardian
  ```

2. Crea un entorno virtual:

  ```bash
  python3 -m venv venv
  source venv/bin/activate  # En Linux/macOS
  venv\Scripts\activate     # En Windows
  ```

3. Instala las dependencias:

  ```bash
  pip install -r requirements.txt
  ```

4. Configura el archivo .env:

Crea un archivo .env en el directorio raíz del proyecto con el siguiente contenido:

  ```env
  TELEGRAM_API_KEY=<TU_TOKEN_DE_TELEGRAM>
  CHAT_ID=<ID_DE_CHAT_TELEGRAM>
  TRUSTED_DEVICES_FILE=trusted_devices.json
  ```

[Cómo crear un bot en Telegram y obtener el API_KEY / CHAT_ID](https://core.telegram.org/api/obtaining_api_id)

5. Construcción de la imagen de Docker:

Es importante tener Docker instalado previamente.
  
  ```bash
  docker build -t networkguardian .
  ```
