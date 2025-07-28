const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'SEGREDO_SUPER_SECRETO_PARA_ASSINAR_OS_TOKENS';

// --- Conexão com o Banco de Dados PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Middlewares
app.use(cors());
app.use(express.json());

// --- Middleware de Autenticação ---
// Verifica o token em cada requisição protegida
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"
    if (token == null) return res.sendStatus(401); // Sem token, sem acesso

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Token inválido
        req.user = user; // Salva as informações do usuário (id, loja_id, role) na requisição
        next(); // Continua para a rota solicitada
    });
}


// --- ROTAS DA API ---

// ROTA DE LOGIN (Agora devolve um token)
app.post('/api/login', async (req, res) => {
    try {
        const { usuario, senha } = req.body;
        const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

        const match = await bcrypt.compare(senha, user.senha);
        if (match) {
            const payload = { userId: user.id, lojaId: user.loja_id, role: user.role };
            const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
            // Retorna o token e o cargo para o frontend
            res.json({ message: "Login bem-sucedido", token: token, role: user.role });
        } else {
            res.status(401).json({ error: "Senha incorreta" });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});


// --- ROTAS PROTEGIDAS ---
// Todas as rotas abaixo agora usam o middleware 'authenticateToken'

// ROTAS DE ESTOQUE
app.get('/api/estoque', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const result = await pool.query('SELECT * FROM estoque WHERE loja_id = $1 ORDER BY nome', [lojaId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/estoque', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const { codigo, nome, preco, quantidade } = req.body;
        const query = `
            INSERT INTO estoque (codigo, nome, preco, quantidade, loja_id) VALUES ($1, $2, $3, $4, $5) 
            ON CONFLICT (codigo) DO UPDATE SET quantidade = estoque.quantidade + $4, preco = $3`;
        await pool.query(query, [codigo, nome, parseFloat(preco), parseInt(quantidade), lojaId]);
        res.status(201).json({ message: "Produto adicionado/atualizado!" });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

// ROTAS DE USUÁRIOS
app.get('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403); // Apenas admin pode listar
    try {
        const { lojaId } = req.user;
        const result = await pool.query('SELECT id, usuario, role FROM usuarios WHERE loja_id = $1 ORDER BY usuario', [lojaId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/usuarios', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.sendStatus(403); // Apenas admin pode criar
    const { usuario, senha, role } = req.body;
    const { lojaId } = req.user;
    if (!usuario || !senha || !role) return res.status(400).json({ error: 'Usuário, senha e cargo são obrigatórios.' });
    try {
        const hash = await bcrypt.hash(senha, SALT_ROUNDS);
        const query = 'INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, $4) RETURNING id';
        await pool.query(query, [usuario, hash, role, lojaId]);
        res.status(201).json({ message: 'Usuário criado com sucesso!'});
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'Este nome de usuário já existe.' });
        res.status(500).json({ error: err.message });
    }
});


// ROTAS DE VENDAS
app.post('/api/vendas', authenticateToken, async (req, res) => {
    const { itens, metodoPagamento, desconto } = req.body;
    const { lojaId } = req.user;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const insertVendaQuery = "INSERT INTO vendas (produto_nome, produto_preco, metodo_pagamento, desconto, loja_id) VALUES ($1, $2, $3, $4, $5)";
        const updateEstoqueQuery = "UPDATE estoque SET quantidade = quantidade - 1 WHERE codigo = $1 AND loja_id = $2 AND quantidade > 0";
        const descontoPorItem = (desconto / itens.length) || 0;
        for (const item of itens) {
            await client.query(insertVendaQuery, [item.nome, item.preco, metodoPagamento, descontoPorItem, lojaId]);
            const estoqueResult = await client.query(updateEstoqueQuery, [item.codigo, lojaId]);
            if (estoqueResult.rowCount === 0) throw new Error(`Estoque insuficiente para o produto ${item.nome}`);
        }
        await client.query('COMMIT');
        res.status(201).json({message: "Vendas registradas e estoque atualizado!"});
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({error: "Erro ao registrar vendas: " + err.message});
    } finally {
        client.release();
    }
});


// --- SERVIR ARQUIVOS DO FRONTEND ---
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});


app.listen(port, () => {
    console.log(`--- Servidor Multi-Tenant com JWT rodando em http://localhost:${port} ---`);
});