from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from typing import Dict
from io import BytesIO

from verify_gost_detached import verify_detached_cms
from report import build_pdf_report

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
    .drop{border:2px dashed #9ca3af;border-radius:12px;padding:18px;margin:10px 0;text-align:center;color:#6b7280}
    .drop.drag{background:#f1f5f9}
  </style>
</head>
<body>
  <h1>Проверка откреплённой подписи ГОСТ 2012</h1>
  <div id="app" class="card">
    <div class="drop" :class="{drag}" @dragover.prevent="drag=true" @dragleave="drag=false" @drop.prevent="onDrop">
      Перетащите сюда сразу два файла: PDF и SIG, либо нажмите чтобы выбрать
      <br/>
      <input type=file multiple style="margin-top:8px" @change="onPick" />
    </div>
    <div class=row>
      <button @click="verify" :disabled="loading">Проверить</button>
      <button v-if="result && result.ok" @click="downloadPDF">Скачать протокол (PDF)</button>
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
      const drag = ref(false)
      const loading = ref(false)
      const error = ref('')
      const result = ref(null)
      const onDrop = (e)=>{
        drag.value = false
        handleFiles(e.dataTransfer.files)
      }
      const onPick = (e)=> handleFiles(e.target.files)
      const handleFiles = (files)=>{
        error.value = ''
        result.value = null
        pdf.value = null
        sig.value = null
        Array.from(files).forEach(f=>{
          if(/\.pdf$/i.test(f.name)) pdf.value = f
          else if(/\.sig$/i.test(f.name)) sig.value = f
        })
        if(!pdf.value || !sig.value){ error.value = 'Нужно выбрать PDF и SIG' }
      }
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
      const downloadPDF = async ()=>{
        const fd = new FormData()
        fd.append('pdf', pdf.value)
        fd.append('sig', sig.value)
        const r = await fetch('/api/report', {method:'POST', body: fd})
        if(!r.ok){ const j = await r.json(); throw new Error(j.detail || 'report failed') }
        const blob = await r.blob()
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = 'report.pdf'; a.click(); URL.revokeObjectURL(url)
      }
      return { pdf, sig, drag, loading, error, result, verify, onDrop, onPick, downloadPDF }
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


 


@app.post("/api/report")
async def api_report(pdf: UploadFile = File(...), sig: UploadFile = File(...)):
    try:
        pdf_bytes = await pdf.read()
        sig_bytes = await sig.read()
        ok, details = verify_detached_cms(pdf_bytes, sig_bytes)
        content = build_pdf_report(ok, details, pdf_name=pdf.filename or 'document.pdf', sig_name=sig.filename or 'signature.sig')
        return StreamingResponse(BytesIO(content), media_type="application/pdf", headers={
            "Content-Disposition": "attachment; filename=report.pdf"
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


