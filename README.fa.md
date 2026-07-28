# CrimsonCF

[အင်္ဂလိပ်](README.md) | [ပါရှန်](README.fa.md)

**CrimsonCF (CrimsonCloudFlare)** သည် Cloudflare အကွာအဝေးများအတွက် မြန်ဆန်သော IP scanner webapp တစ်ခုဖြစ်ပြီး **L4 TCP Handshake** (HTTPS မဟုတ်ပါ) ဖြင့် စမ်းသပ်ကာ ရလဒ်များကို သိမ်းဆည်းပြီး **Xray / sing-box / Clash** ကဲ့သို့သော proxy tool များအတွက် အသင့်သုံး output ကို ဖန်တီးပေးသည်။

![CrimsonCF webapp screenshot](docs/screenshot.png)

## အဘယ်ကြောင့် CrimsonCF ကို ရွေးချယ်သင့်သနည်း။

- layer 4 တွင် အမှန်တကယ် စမ်းသပ်ခြင်း- TCP ချိတ်ဆက်မှုကိုသာ စစ်ဆေးသောကြောင့် `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` ကဲ့သို့သော အမှားများသည် ပြဿနာမဟုတ်ပါ။

- တစ်ပြိုင်နက်တည်း စကင်ဖတ်ခြင်း
- စကင်ဖတ်မှတ်တမ်းနှင့် အထွက်
- IP အပိုင်းအခြားများ၏ အုပ်စုဖွဲ့ခြင်းနှင့် စာမျက်နှာခွဲခြားခြင်း
- TXT အထွက် (IP တစ်ခုစီကို တစ်လိုင်းတွင်)
- DNS panel: Cloudflare A record တွင် အမြန်ဆုံး IP များကို မှတ်ပုံတင်ပါ

## Docker Compose ဖြင့် ဒေသတွင်းတွင် လုပ်ဆောင်ပါ (အကြံပြုထားသည်)

ကြိုတင်လိုအပ်ချက်- Docker

```bash
docker compose up -d
```

ထို့နောက်-

သင့် system တွင် လုပ်ဆောင်ပါ
- : `http://localhost:8080`

---

အင်္ဂလိပ် README: `README.md`

OpenAI ChatGPT (Codex) မှ အကူအညီဖြင့် `github.com/amir0zx` မှ ဖန်တီးထားသည်။
