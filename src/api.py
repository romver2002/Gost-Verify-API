from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from typing import Dict

from verify_gost_detached import verify_detached_cms

app = FastAPI(title="GOST 2012 Verify API")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """
<!doctype html>
<html lang=ru>
<head>
  <meta charset=utf-8 />
  <meta name=viewport content="width=device-width, initial-scale=1" />
  <title>Проверка подписи ГОСТ 2012</title>
  <link rel="preconnect" href="https://cdn.jsdelivr.net" />
  <script src="https://cdn.jsdelivr.net/npm/vue@3.4.29/dist/vue.global.prod.js"></script>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;max-width:920px;margin:24px auto;padding:0 16px}
    .card{border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin-top:16px}
    .row{display:flex;gap:8px;flex-wrap:wrap}
    input[type=file]{padding:10px;border:1px solid #e5e7eb;border-radius:8px;background:#fff}
    button{padding:10px 14px;border-radius:8px;border:0;background:#2563eb;color:#fff;cursor:pointer}
    pre{background:#0b1020;color:#d6e2ff;padding:12px;border-radius:8px;overflow:auto}
    .ok{color:#059669}
    .err{color:#dc2626}
  </style>
</head>
<body>
  <h1>Проверка откреплённой подписи ГОСТ 2012</h1>
  <div id="app" class="card">
    <div class=row>
      <input type=file @change="e=>pdf=e.target.files[0]" accept="application/pdf" />
      <input type=file @change="e=>sig=e.target.files[0]" />
      <button @click="verify" :disabled="loading">Проверить</button>
    </div>
    <div v-if="error" class="err" style="margin-top:12px">{{ error }}</div>
    <div v-if="result" class="card">
      <div v-if="result.ok" class=ok><strong>Signature OK</strong></div>
      <div v-else class=err><strong>Signature FAIL</strong></div>
      <pre>{{ JSON.stringify(result.details, null, 2) }}</pre>
    </div>
  </div>
  <script>
  const { createApp, ref } = Vue
  createApp({
    setup(){
      const pdf = ref(null)
      const sig = ref(null)
      const loading = ref(false)
      const error = ref('')
      const result = ref(null)
      const verify = async ()=>{
        error.value = ''
        result.value = null
        if(!pdf.value || !sig.value){
          error.value = 'Загрузите PDF и SIG'
          return
        }
        loading.value = true
        try{
          const fd = new FormData()
          fd.append('pdf', pdf.value)
          fd.append('sig', sig.value)
          const res = await fetch('/api/verify', { method: 'POST', body: fd })
          const json = await res.json()
          if(!res.ok){ throw new Error(json.detail || 'Verify failed') }
          result.value = json
        }catch(e){ error.value = e.message }
        finally{ loading.value = false }
      }
      return { pdf, sig, loading, error, result, verify }
    }
  }).mount('#app')
  </script>
</body>
</html>
"""


@app.post("/api/verify")
async def api_verify(pdf: UploadFile = File(...), sig: UploadFile = File(...)) -> Dict:
    try:
        pdf_bytes = await pdf.read()
        sig_bytes = await sig.read()
        ok, details = verify_detached_cms(pdf_bytes, sig_bytes)
        return {"ok": ok, "details": details}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


