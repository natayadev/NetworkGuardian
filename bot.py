import os
import json
import logging
import socket
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters, JobQueue

load_dotenv()
TELEGRAM_API_KEY = os.getenv("TELEGRAM_API_KEY")
CHAT_ID = os.getenv("CHAT_ID")
TRUSTED_DEVICES_FILE = os.getenv("TRUSTED_DEVICES_FILE", "trusted_devices.json")
WHITELIST_PATH = "whitelist.json"

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Conectar a una IP pública cualquiera (Google DNS)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_local_network():
    ip = get_local_ip()
    parts = ip.split('.')
    # Retorna la subred, por ejemplo: "192.168.1.1/24"
    network = '.'.join(parts[:3]) + '.1/24'
    return network


# Funciones auxiliares para dispositivos confiables
def load_trusted_devices():
    if os.path.exists(TRUSTED_DEVICES_FILE):
        with open(TRUSTED_DEVICES_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_trusted_devices(devices):
    with open(TRUSTED_DEVICES_FILE, 'w') as f:
        json.dump(devices, f, indent=4)

# Escaneo de red
def scan_network():
    devices = {}
    target_ip =  get_local_network()
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        devices[element[1].psrc] = element[1].hwsrc
    return devices

# Funciones auxiliares para whitelist con MAC y nombre
def load_whitelist():
    if os.path.exists(WHITELIST_PATH):
        with open(WHITELIST_PATH, "r") as f:
            return json.load(f)
    return []

def save_whitelist(data):
    with open(WHITELIST_PATH, "w") as f:
        json.dump(data, f, indent=4)

def get_trusted_macs():
    whitelist = load_whitelist()
    return [entry['mac'].lower() for entry in whitelist]

def add_trusted_entry(name, mac):
    whitelist = load_whitelist()
    if any(entry["mac"].lower() == mac.lower() for entry in whitelist):
        return False, "⚠️ Ya existe un dispositivo con esa MAC."
    whitelist.append({"name": name, "mac": mac})
    save_whitelist(whitelist)
    return True, f"✅ Dispositivo '{name}' con MAC {mac} agregado a la whitelist."

def remove_trusted_entry(mac):
    whitelist = load_whitelist()
    new_whitelist = [entry for entry in whitelist if entry["mac"].lower() != mac.lower()]
    if len(new_whitelist) == len(whitelist):
        return False, "❌ No se encontró un dispositivo con esa MAC."
    save_whitelist(new_whitelist)
    return True, "🗑️ Dispositivo eliminado de la whitelist."


# Comando /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        '¡Hola! Estoy listo para notificarte cuando un nuevo dispositivo se conecte a la red. '
        'Escribe /help para más información. 😊'
    )

# Comando /help: Instrucciones sobre cómo usar el bot
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "Comandos disponibles: \n"
        "/start - Inicia el bot. \n"
        "/scan - Escanea manualmente la red y muestra dispositivos no confiables. \n"
        "/trusted - Muestra los dispositivos confiables registrados. \n"
    )
    await update.message.reply_text(help_text)

# Comando /scan: Escaneo manual
async def manual_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    devices = scan_network()
    trusted_macs = get_trusted_macs()

    new_devices = []
    for ip, mac in devices.items():
        if mac.lower() not in trusted_macs:
            new_devices.append(f"IP: {ip}, MAC: {mac}")

    if new_devices:
        message = "🔍 Dispositivos no confiables detectados:\n" + "\n".join(new_devices)
    else:
        message = "✅ No se detectaron nuevos dispositivos no confiables en la red."

    await update.message.reply_text(message)


# /trusted
async def list_trusted_devices(update: Update, context: ContextTypes.DEFAULT_TYPE):
    whitelist = load_whitelist()
    if whitelist:
        message = "🔒 Dispositivos confiables:\n"
        for entry in whitelist:
            message += f"MAC: {entry['mac']}, Alias: {entry['name']}\n"
    else:
        message = "🚫 No hay dispositivos confiables registrados."
    await update.message.reply_text(message)


# /add_trusted nombre MAC
async def add_trusted(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        name, mac = context.args
        success, msg = add_trusted_entry(name, mac)
        await update.message.reply_text(msg)
    except ValueError:
        await update.message.reply_text("⚠️ Uso correcto: /add_trusted nombre MAC")

# /remove_trusted MAC
async def remove_trusted(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        mac = context.args[0]
        success, msg = remove_trusted_entry(mac)
        await update.message.reply_text(msg)
    except IndexError:
        await update.message.reply_text("⚠️ Uso correcto: /remove_trusted MAC")


# Manejo de nuevos dispositivos y alias
async def handle_trust_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    # Asumimos que si el texto tiene 17 caracteres y formato MAC (xx:xx:xx:xx:xx:xx) es MAC
    if len(text) == 17 and text.count(":") == 5:
        mac_address = text.lower()
        whitelist = load_whitelist()
        macs = [entry['mac'].lower() for entry in whitelist]
        if mac_address in macs:
            await update.message.reply_text(f"🔐 El dispositivo con MAC {mac_address} ya es confiable.")
        else:
            await update.message.reply_text(
                f"Nuevo dispositivo detectado con MAC {mac_address}. Envíame el alias que quieres asignarle. ✨"
            )
            context.user_data['mac_address'] = mac_address
    else:
        # Si se espera alias, se guarda el alias
        mac_address = context.user_data.get('mac_address')
        if mac_address:
            alias = text
            whitelist = load_whitelist()
            whitelist.append({"mac": mac_address, "name": alias})
            save_whitelist(whitelist)
            await update.message.reply_text(f"🔒 El dispositivo {mac_address} ahora es confiable con alias '{alias}'.")
            context.user_data.clear()
        else:
            await update.message.reply_text("❌ No reconozco ese comando o formato. Usa /help para ayuda.")

# Comando para confiar en un dispositivo
async def trust_device(update: Update, context: ContextTypes.DEFAULT_TYPE):
    mac_address = context.user_data.get('mac_address')
    alias = update.message.text.strip()

    if mac_address:
        trusted_devices = load_trusted_devices()
        trusted_devices[mac_address] = alias
        save_trusted_devices(trusted_devices)
        await update.message.reply_text(f"🔒 El dispositivo {mac_address} ahora es confiable con alias '{alias}'.")
    else:
        await update.message.reply_text("⚠️ No se encontró un dispositivo para confiar.")

    context.user_data.clear()

# Notificación de dispositivos no confiables
async def notify_new_devices(context: ContextTypes.DEFAULT_TYPE):
    devices = scan_network()
    trusted_macs = get_trusted_macs()

    for ip, mac in devices.items():
        if mac.lower() not in trusted_macs:
            message = f"⚠️ Nuevo dispositivo con MAC {mac} detectado en la red."
            await context.bot.send_message(chat_id=CHAT_ID, text=message)

# Manejo de comandos no válidos
async def invalid_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Comando no reconocido. Escribe /help para ver los comandos disponibles.")

def main():
    logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)

    application = Application.builder().token(TELEGRAM_API_KEY).build()

    application.add_handler(CommandHandler('start', start))
    application.add_handler(CommandHandler('help', help_command))
    application.add_handler(CommandHandler('scan', manual_scan))
    application.add_handler(CommandHandler('trusted', list_trusted_devices))

    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_trust_request))

    application.add_handler(MessageHandler(filters.COMMAND, invalid_command))

    job_queue: JobQueue = application.job_queue
    #job_queue.run_repeating(notify_new_devices, interval=30, first=0)

    application.run_polling()

if __name__ == '__main__':
    main()