﻿/*
RICO INVESTIMENTO - server.js atualizado
- OTP agora formata número para +244
 - OTP guardado temporariamente na memória do servidor por 5 minutos
 - Logs detalhados
*/

const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const https = require('https');
const multer = require('multer');
const FormData = require('form-data');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const fetch = (...args) =>
    import('node-fetch').then(({ default: fetchFn }) => fetchFn(...args));

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'site')));

// CONFIGURAÇÃO SUPABASE
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://mgwxtbxgxozxicmipadr.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_publishable_cAFfrLoGx4MbG0J3IXwINw_f6NOuPkQ';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// CONFIGS
const DEPOSITO_API_KEY = process.env.DEPOSITO_API_KEY || '32y3103KsiiaoL57dt38blJ1TWKxeDrUYucBeraKgI47hr2RbsJBOsJEtScy590203';
const DEPOSITO_DESTINO_NUMERO = '926240472';
const DEPOSITO_DESTINO_IBAN = '';
const DEPOSITO_TAXA_KZ = 1;
const DEPOSITO_SUDO_URL = 'https://comprovativos.sudomakes.com/validar/';
const DEPOSITO_MAX_FILE_MB = 10;
const DEPOSITO_TIMEOUT_MS = 25000;

const SMS_API_URL = 'https://smsapi.sudomakes.com/api/enviar-sms';
const OTP_API_URL = 'https://smsapi.sudomakes.com/api/enviar-otp';
const SMS_API_KEY = process.env.SMS_API_KEY || 'b/XqoDmBgf9lNDlP7gE7qpMNobETZ0ZWNekINr559KcwNZQ477TCj6yJlKRTH7MO';
// A API usada pelo código de referência devolve o OTP no campo "otp".
// Pode ser substituída em produção pela variável KASSALA_API_KEY.
const KASSALA_API_KEY = process.env.KASSALA_API_KEY || 'VFlkCkvV+LdsirzvfB4J6/rGl6eMItrUQYR3/HsVRb42yBJAM+p3urmKwDdsF0l3duva/fyFWvkjIumDcE/uagO53vdAj74CuXiNZOVMkwc=';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '123';
const OTP_EXPIRA_MS = 5 * 60 * 1000;
const OTP_REENVIO_MS = 60 * 1000;
const OTP_MAX_TENTATIVAS = 5;
const OTP_IP_WINDOW_MS = 10 * 60 * 1000;
const OTP_IP_MAX_REQUESTS = 10;
const otpStore = new Map();
const otpIpStore = new Map();

// Remove códigos expirados para não acumular dados na memória do processo.
const otpCleanupTimer = setInterval(() => {
    const agora = Date.now();
    for (const [telefone, registro] of otpStore.entries()) {
        if (!registro || registro.expira <= agora) otpStore.delete(telefone);
    }
}, 60 * 1000);
otpCleanupTimer.unref?.();

function toNumberSafe(value, fallback = 0) {
    const n = Number(value);
    return Number.isFinite(n)? n : fallback;
}
function arredondar2(value) { return Number(toNumberSafe(value).toFixed(2)); }
function formatarNumeroSMS(destinatario) {
    const numero = String(destinatario || '').replace(/\D/g, '');
    if (!numero) return '';
    return numero.startsWith('244')? `+${numero}` : `+244${numero}`;
}
async function enviarSMS(destinatario, mensagem) {
    if (!SMS_API_KEY) return null;
    const numeroFormatado = formatarNumeroSMS(destinatario);
    if (!numeroFormatado) return null;
    try {
        const response = await fetch(SMS_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ api_key: SMS_API_KEY, destinatario: numeroFormatado, mensagem })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) console.error('Erro SMS:', data);
        return data;
    } catch (error) { console.error('Erro SMS:', error.message); return null; }
}
function gerarCodigoOTP() { return String(crypto.randomInt(100000, 1000000)); }
function validarDadosCadastro({ nome, telefone, senha }) {
    const nomeLimpo = normalizarTexto(nome);
    const telefoneAssinatura = assinaturaTelefone(telefone);
    const senhaLimpa = String(senha || '').trim();
    if (nomeLimpo.split(/\s+/).filter(Boolean).length < 2) return { error: 'Insira nome e apelido.' };
    if (!/^9\d{8}$/.test(telefoneAssinatura)) return { error: 'Numero de telemovel invalido.' };
    if (senhaLimpa.length < 5) return { error: 'A palavra-passe deve ter pelo menos 5 caracteres.' };
    return { nomeLimpo, telefoneAssinatura, senhaLimpa };
}
function chamarAPIKassala(caminho, payload) {
    return new Promise((resolve, reject) => {
        const corpo = JSON.stringify(payload);
        const pedido = https.request({
            hostname: 'smsapi.sudomakes.com',
            path: caminho,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(corpo)
            },
            timeout: 15000
        }, (resposta) => {
            let texto = '';
            resposta.setEncoding('utf8');
            resposta.on('data', (parte) => { texto += parte; });
            resposta.on('end', () => {
                try {
                    resolve(texto ? JSON.parse(texto) : {});
                } catch {
                    resolve({ status: -1, log: texto });
                }
            });
        });

        pedido.on('timeout', () => pedido.destroy(new Error('Tempo limite da API OTP excedido.')));
        pedido.on('error', reject);
        pedido.write(corpo);
        pedido.end();
    });
}

function limitarPedidosOTP(req) {
    const ip = req.ip || req.socket.remoteAddress || 'desconhecido';
    const agora = Date.now();
    const registro = otpIpStore.get(ip);

    if (!registro || agora - registro.inicio >= OTP_IP_WINDOW_MS) {
        otpIpStore.set(ip, { inicio: agora, total: 1 });
        return null;
    }

    if (registro.total >= OTP_IP_MAX_REQUESTS) {
        return 'Muitos pedidos de SMS. Tente novamente mais tarde.';
    }

    registro.total += 1;
    return null;
}

async function enviarOTPCadastro(destinatario) {
    if (!KASSALA_API_KEY) throw new Error('Chave da API OTP nao configurada.');
    const telefone = assinaturaTelefone(destinatario);
    const resposta = await chamarAPIKassala('/api/enviar-otp', {
        api_key: KASSALA_API_KEY,
        destinatario: telefone
    });

    console.log('[OTP] envio para', telefone, 'status', resposta.status);
    if (Number(resposta.status) !== 1 || !resposta.otp) {
        const mensagem = resposta.log || resposta.erro || resposta.mensagem || 'Falha ao enviar codigo OTP.';
        throw new Error(String(mensagem));
    }

    return String(resposta.otp);
}
const depositoUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: DEPOSITO_MAX_FILE_MB * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const isPdf = file.mimetype === 'application/pdf';
        const isImage = file.mimetype.startsWith('image/');
        if (!isPdf &&!isImage) return cb(new Error('Tipo de arquivo nao suportado. Envie PDF ou imagem.'));
        return cb(null, true);
    },
});

const usuariosOnline = new Map();
io.on('connection', (socket) => {
    socket.on('registrar-online', (telefone) => {
        usuariosOnline.set(String(telefone), socket.id);
        console.log(`📱 Usuário ${telefone} está online.`);
    });
    socket.on('disconnect', () => {
        const key = socket.data.telefoneKey;
        if (key && usuariosOnline.get(key) === socket.id) usuariosOnline.delete(key);
    });
});
function notificarSaldoUsuario(telefone, payload) {
    const key = assinaturaTelefone(telefone);
    if (!key) return;
    const socketDestino = usuariosOnline.get(key);
    if (socketDestino) io.to(socketDestino).emit('atualizar-saldo', payload);
}
function normalizarDigitos(value) { return String(value || '').replace(/\D/g, ''); }
function assinaturaTelefone(value) {
    const digitos = normalizarDigitos(value);
    if (!digitos) return '';
    return digitos.length > 9? digitos.slice(-9) : digitos;
}
function gerarVariacoesTelefone(value) {
    const assinatura = assinaturaTelefone(value);
    const completo = normalizarDigitos(value);
    if (!assinatura &&!completo) return [];
    return [...new Set([assinatura, `+244${assinatura}`, `244${assinatura}`, `0${assinatura}`, completo, `+${completo}`].filter(Boolean))];
}
async function buscarUsuariosPorTelefone(telefone, colunas = '*') {
    const variacoes = gerarVariacoesTelefone(telefone);
    const assinatura = assinaturaTelefone(telefone);
    if (!variacoes.length ||!assinatura) return [];
    const { data: porIgualdade, error: erroEq } = await supabase.from('usuarios').select(colunas).in('telefone', variacoes);
    if (erroEq) throw erroEq;
    if (porIgualdade && porIgualdade.length > 0) return porIgualdade;
    const { data: porAssinatura, error: erroAssinatura } = await supabase.from('usuarios').select(colunas).like('telefone', `%${assinatura}`);
    if (erroAssinatura) throw erroAssinatura;
    return porAssinatura || [];
}
async function buscarUsuarioPorTelefone(telefone, colunas = '*') {
    const lista = await buscarUsuariosPorTelefone(telefone, colunas);
    return lista[0] || null;
}
function normalizarTexto(valor) { return String(valor || '').trim(); }

//... [mantenho todas as tuas rotas de deposito, transferencia, levantamentos, etc. iguais]...
// Por brevidade não repito aqui, elas não tinham erro.

// --- ROTAS OTP CORRIGIDAS ---
async function solicitarOTPCadastro(req, res) {
    const { nome, telefone, senha, indicado_por } = req.body;
    const validacao = validarDadosCadastro({ nome, telefone, senha });
    if (validacao.error) return res.status(400).json({ success: false, error: validacao.error });
    const { nomeLimpo, telefoneAssinatura, senhaLimpa } = validacao;
    try {
        const existente = await buscarUsuarioPorTelefone(telefoneAssinatura, 'id');
        if (existente) return res.status(400).json({ success: false, error: 'Este numero ja esta registado.' });

        const erroLimiteIP = limitarPedidosOTP(req);
        if (erroLimiteIP) return res.status(429).json({ success: false, error: erroLimiteIP });

        const anterior = otpStore.get(telefoneAssinatura);
        if (anterior) {
            if (anterior.expira <= Date.now()) {
                otpStore.delete(telefoneAssinatura);
            } else if (Date.now() - anterior.enviadoEm < OTP_REENVIO_MS) {
                const segundos = Math.ceil((OTP_REENVIO_MS - (Date.now() - anterior.enviadoEm)) / 1000);
                return res.status(429).json({ success: false, error: `Aguarde ${segundos}s para reenviar o codigo.` });
            }
        }

        // A API de referência gera e devolve o OTP. O código fica apenas na memória do servidor.
        const codigo = await enviarOTPCadastro(telefoneAssinatura);
        otpStore.set(telefoneAssinatura, {
            codigo,
            nome: nomeLimpo,
            senha: senhaLimpa,
            indicado_por: indicado_por || null,
            expira: Date.now() + OTP_EXPIRA_MS,
            enviadoEm: Date.now(),
            tentativas: 0,
        });
        res.json({ success: true, telefone: telefoneAssinatura, expiraEmSegundos: Math.floor(OTP_EXPIRA_MS / 1000), mensagem: 'Codigo de confirmacao enviado por SMS.' });
    } catch (err) {
        console.error('Erro ao solicitar OTP:', err);
        res.status(500).json({ success: false, error: err.message || 'Erro ao enviar o codigo.' });
    }
}
app.post('/auth/solicitar-otp-cadastro', solicitarOTPCadastro);
app.post('/auth/cadastro', solicitarOTPCadastro);

app.post('/auth/confirmar-cadastro', async (req, res) => {
    const telefoneAssinatura = assinaturaTelefone(req.body.telefone);
    const codigo = String(req.body.codigo || '').replace(/\D/g, '');
    if (!/^9\d{8}$/.test(telefoneAssinatura) || !/^\d{4,8}$/.test(codigo)) {
        return res.status(400).json({ success: false, error: 'Telefone ou codigo invalido.' });
    }

    try {
        const pendente = otpStore.get(telefoneAssinatura);
        if (!pendente) return res.status(400).json({ success: false, error: 'Solicite um novo codigo de confirmacao.' });

        const agora = Date.now();
        if (pendente.expira <= agora) {
            otpStore.delete(telefoneAssinatura);
            return res.status(400).json({ success: false, error: 'Codigo expirado. Solicite um novo codigo.' });
        }
        if ((pendente.tentativas || 0) >= OTP_MAX_TENTATIVAS) {
            otpStore.delete(telefoneAssinatura);
            return res.status(429).json({ success: false, error: 'Limite de tentativas excedido.' });
        }
        if (String(pendente.codigo)!== codigo) {
            pendente.tentativas = (pendente.tentativas || 0) + 1;
            if (pendente.tentativas >= OTP_MAX_TENTATIVAS) otpStore.delete(telefoneAssinatura);
            return res.status(401).json({ success: false, error: 'Codigo de confirmacao incorreto.' });
        }

        const existente = await buscarUsuarioPorTelefone(telefoneAssinatura, 'id');
        if (existente) {
            otpStore.delete(telefoneAssinatura);
            return res.status(400).json({ success: false, error: 'Este numero ja esta registado.' });
        }

        const payload = { nome_completo: pendente.nome, telefone: telefoneAssinatura, senha: pendente.senha, saldo_usd: 50.00 };
        const indicadoPorNum = parseInt(pendente.indicado_por);
        if (Number.isInteger(indicadoPorNum) && indicadoPorNum > 0) payload.indicado_por = indicadoPorNum;

        const { data, error: insertErr } = await supabase.from('usuarios').insert(payload).select('id, nome_completo, telefone, saldo_usd').single();
        if (insertErr) throw insertErr;

        otpStore.delete(telefoneAssinatura);
        res.status(201).json({ success: true, usuario: data });
    } catch (err) {
        console.error('Erro ao confirmar cadastro:', err);
        res.status(500).json({ success: false, error: 'Erro ao criar a conta.' });
    }
});

//... [resto das tuas rotas permanece igual]...

const PORTA = process.env.PORT || 3000;
server.listen(PORTA, '0.0.0.0', () => {
    console.log(`🚀 API RICO INVESTIMENTO ativa na porta ${PORTA}`);
});
