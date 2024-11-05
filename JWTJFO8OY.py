import random
import string
import json
import time
import hmac
import hashlib
import base64
import requests
from telegram import Update, ParseMode
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# تعريف المستخدم المصرح له باستخدام البوت (مثال على ID المستخدم)
AUTHORIZED_USER_ID = 7608866212  # استبدله بمعرف Telegram الخاص بالمستخدم المصرح له

# دوال مساعدة
def generate_random_id(length=10):
    return ''.join(random.choices(string.digits, k=length))

def generate_jwt_token(uid, name, server):
    # إعدادات JSON Web Token
    header = json.dumps({'typ': 'JWT', 'alg': 'HS256'})
    payload = json.dumps({
        'uid': uid,
        'name': name,
        'server': server,
        'exp': int(time.time()) + (8 * 60 * 60)  # انتهاء التوكن بعد 8 ساعات
    })

    # تشفير Base64 لكل من الهيدر والبايلود
    base64_url_header = base64.urlsafe_b64encode(header.encode()).decode().rstrip("=")
    base64_url_payload = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")

    # توقيع التوكن
    secret = 'hplvl'  # استبدل المفتاح السري بمفتاحك الخاص
    signature = hmac.new(secret.encode(), (base64_url_header + "." + base64_url_payload).encode(), hashlib.sha256).digest()
    base64_url_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    # التوكن النهائي
    return f"{base64_url_header}.{base64_url_payload}.{base64_url_signature}"

def get_player_info(player_id):
    # إعداد ملفات تعريف (cookies) كما هو في الكود المقدم
    cookies = {
        '_ga': 'GA1.1.2123120599.1674510784',
        '_fbp': 'fb.1.1674510785537.363500115',
        '_ga_7JZFJ14B0B': 'GS1.1.1674510784.1.1.1674510789.0.0.0',
        'source': 'mb',
        'region': 'MA',
        'language': 'ar',
        '_ga_TVZ1LG7BEB': 'GS1.1.1674930050.3.1.1674930171.0.0.0',
        'datadome': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
        'session_key': 'efwfzwesi9ui8drux4pmqix4cosane0y',
    }

    headers = {
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
        'Origin': 'https://shop2game.com',
        'Referer': 'https://shop2game.com/app/100067/idlogin',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 11; Redmi Note 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36',
        'accept': 'application/json',
        'content-type': 'application/json',
        'sec-ch-ua': '"Chromium";v="107", "Not=A?Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'x-datadome-clientid': '6h5F5cx_GpbuNtAkftMpDjsbLcL3op_5W5Z-npxeT_qcEe_7pvil2EuJ6l~JlYDxEALeyvKTz3~LyC1opQgdP~7~UDJ0jYcP5p20IQlT3aBEIKDYLH~cqdfXnnR6FAL0',
    }

    json_data = {
        'app_id': 100067,
        'login_id': f'{player_id}',
        'app_server_id': 0,
    }

    res = requests.post('https://shop2game.com/api/auth/player_id_login', cookies=cookies, headers=headers, json=json_data)

    if res.status_code == 200:
        response = res.json()
        name = response.get('nickname')
        region = response.get('region')
        
        return {'name': name, 'region': region} if name and region else None
    else:
        return None

# استجابة الأمر /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != AUTHORIZED_USER_ID:
        await update.message.reply_text("عذراً، غير مصرح لك باستخدام هذا البوت.")
        return

    welcome_message = "**أهلاً بك في بوت HP LVL لتوكنات JWT**\n\n"
    welcome_message += "لإرسال TOKEN JWT اكتب /token\n"
    welcome_message += "IG : @HMAXLAB.\n"
    await update.message.reply_text(welcome_message, parse_mode=ParseMode.MARKDOWN)

# استجابة الأمر /token
async def token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != AUTHORIZED_USER_ID:
        await update.message.reply_text("عذراً، غير مصرح لك باستخدام هذا البوت.")
        return

    player_id = generate_random_id()
    player_info = get_player_info(player_id)

    if player_info:
        jwt_token = generate_jwt_token(player_id, player_info['name'], player_info['region'])
        response_message = f"**JWT TOKEN**: `{jwt_token}`\n\n"
        response_message += f"**UID**: `{player_id}`\n"
        response_message += f"**Name**: `{player_info['name']}`\n"
        response_message += f"**Server**: `{player_info['region']}`\n"
        response_message += "**التوكن تنتهي صلاحيته بعد 8 ساعات**"
        await update.message.reply_text(response_message, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text("تعذر الحصول على معلومات اللاعب.")

# الإعداد الأساسي وتحديد الأوامر
app = ApplicationBuilder().token("7842136443:AAEET0nbQ6w_N1HDn9rhvOBjPeukvsBciNM").build()  # ضع توكن البوت هنا
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("token", token))

# تشغيل البوت
if __name__ == "__main__":
    print("Bot is running...")
    app.run_polling()