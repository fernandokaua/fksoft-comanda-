// VERSÃO FINAL E ROBUSTA - VERIFICA E CRIA COLUNAS SE NECESSÁRIO

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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json());

// --- Função de Setup do Banco de Dados (Versão Robusta) ---
async function setupDatabase() {
    const client = await pool.connect();
    try {
        console.log("Conectado ao PostgreSQL! Verificando estrutura do banco de dados...");
        
        // Função auxiliar para verificar e adicionar colunas
        const addColumnIfNotExists = async (tableName, columnName, columnType) => {
            const res = await client.query(`
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = $1 AND column_name = $2`, [tableName, columnName]);
            if (res.rowCount === 0) {
                await client.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`);
                console.log(`>> Coluna '${columnName}' adicionada à tabela '${tableName}'.`);
            }
        };

        // Cria tabelas se não existirem
        await client.query(`CREATE TABLE IF NOT EXISTS lojas (id SERIAL PRIMARY KEY, nome TEXT NOT NULL)`);
        await client.query(`CREATE TABLE IF NOT EXISTS usuarios (id SERIAL PRIMARY KEY, usuario TEXT UNIQUE NOT NULL, senha TEXT NOT NULL, role TEXT NOT NULL)`);
        await client.query(`CREATE TABLE IF NOT EXISTS estoque (id SERIAL PRIMARY KEY, codigo TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, preco REAL NOT NULL, quantidade INTEGER NOT NULL)`);
        await client.query(`CREATE TABLE IF NOT EXISTS vendas (id SERIAL PRIMARY KEY, produto_nome TEXT NOT NULL, produto_preco REAL NOT NULL, metodo_pagamento TEXT NOT NULL, desconto REAL DEFAULT 0, data_venda TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP)`);
        await client.query(`CREATE TABLE IF NOT EXISTS compras (id SERIAL PRIMARY KEY, produto TEXT NOT NULL, valor REAL NOT NULL, metodo_pagamento TEXT NOT NULL, data_compra DATE NOT NULL)`);
        
        // Verifica e adiciona as colunas loja_id
        await addColumnIfNotExists('usuarios', 'loja_id', 'INTEGER REFERENCES lojas(id)');
        await addColumnIfNotExists('estoque', 'loja_id', 'INTEGER REFERENCES lojas(id)');
        await addColumnIfNotExists('vendas', 'loja_id', 'INTEGER REFERENCES lojas(id)');
        await addColumnIfNotExists('compras', 'loja_id', 'INTEGER REFERENCES lojas(id)');

        console.log(">> Estrutura de tabelas e colunas verificada.");

        // Popula dados iniciais se necessário
        const lojasRes = await client.query('SELECT * FROM lojas LIMIT 1');
        if (lojasRes.rowCount === 0) {
            await client.query("INSERT INTO lojas (nome) VALUES ('Loja Padrão')");
            console.log('>> Loja Padrão criada.');
        }

        const adminRes = await client.query('SELECT * FROM usuarios WHERE usuario = $1', ['admin']);
        if (adminRes.rowCount === 0) {
            const adminPass = 'admin123';
            const hash = await bcrypt.hash(adminPass, SALT_ROUNDS);
            await client.query('INSERT INTO usuarios (usuario, senha, role, loja_id) VALUES ($1, $2, $3, $4)', ['admin', hash, 'admin', 1]);
            console.log('>> Usuário "admin" criado e associado à Loja Padrão.');
        } else {
            // Garante que o usuário admin antigo tenha uma loja_id
            await client.query("UPDATE usuarios SET loja_id = 1 WHERE usuario = 'admin' AND loja_id IS NULL");
        }
        
        console.log('Tabelas do banco de dados prontas.');
    } catch (err) {
        console.error('Erro CRÍTICO durante o setup do banco de dados:', err);
        process.exit(1);
    } finally {
        client.release();
    }
}


// --- Middleware e Rotas (O restante do arquivo continua o mesmo) ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
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
            res.json({ message: "Login bem-sucedido", token: token, role: user.role });
        } else { res.status(401).json({ error: "Senha incorreta" }); }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/estoque', authenticateToken, async (req, res) => {
    try {
        const { lojaId } = req.user;
        const result = await pool.query('SELECT * FROM estoque WHERE loja_id = $1 ORDER BY nome', [lojaId]);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ... Cole aqui TODAS as outras rotas (POST de estoque, usuários, vendas, etc.) da versão completa anterior ...


app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

setupDatabase().then(() => {
    app.listen(port, () => {
        console.log(`--- Servidor pronto para conexões na porta ${port} ---`);
    });
}).catch(err => {
    console.error("Falha ao iniciar o servidor:", err);
});