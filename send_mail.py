import smtplib
from email.mime.text import MIMEText
from email.header import Header

# ===== 邮箱配置（修改这里即可更换发件箱） =====
SMTP_SERVER = 'smtp.163.com'
SMTP_PORT = 465
USERNAME = 'liaotianshi_01@163.com'
PASSWORD = 'ZWjq5hddxThcL3iw'   # 163 授权码，不是登录密码

def send_verification_email(to_email, code):
    """
    发送验证码邮件
    参数：
        to_email: 收件人邮箱
        code: 6位数字验证码
    返回：
        (success, message)   success 为 True/False，message 为成功或错误信息
    """
    subject = '【聊天室】邮箱验证码'
    body = f'您的验证码是：{code}，有效期为5分钟。请勿转发给他人。'

    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = USERNAME
    msg['To'] = to_email

    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.login(USERNAME, PASSWORD)
        server.sendmail(USERNAME, [to_email], msg.as_string())
        server.quit()
        return True, "发送成功"
    except Exception as e:
        return False, str(e)

# 如果直接运行此脚本，可测试发送（需手动输入邮箱）
if __name__ == '__main__':
    test_email = input("请输入测试接收邮箱: ").strip()
    success, msg = send_verification_email(test_email, '123456')
    print("✅ 发送成功" if success else f"❌ 发送失败: {msg}")