
from flask import Flask, render_template, request, redirect, url_for, flash, session
import fdb
from flask_bcrypt import Bcrypt


# CONFIGURACAO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta_ativa_fitness'

bcrypt = Bcrypt(app)


# CONEXAO COM O BANCO DE DADOS

host = 'localhost'
database = r'C:\Users\Aluno\Downloads\BANCO.FDB'
user = 'sysdba'
password = 'sysdba'

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)


# CODIGO DO PERFIL DE ALUNO
# CONFIRME SE O NUMERO 1 E O CORRETO NO SEU BANCO.

PERFIL_ALUNO = 1


# VERIFICAR SE A SENHA E FORTE

def senha_forte(senha):

    if len(senha) < 8:
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_especial = False

    for caractere in senha:

        if caractere.isupper():
            tem_maiuscula = True

        elif caractere.islower():
            tem_minuscula = True

        elif caractere.isdigit():
            tem_numero = True

        else:
            tem_especial = True

    return (
        tem_maiuscula
        and tem_minuscula
        and tem_numero
        and tem_especial
    )


# PAGINA INICIAL

@app.route('/')
def home():
    return render_template('home.html')


# LOGIN

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form.get('email')
        senha = request.form.get('senha')

        if not email or not senha:
            flash('Preencha o email e a senha.')
            return redirect(url_for('login'))

        cursor = con.cursor()

        try:

            cursor.execute("""
                SELECT
                    id_usuario,
                    nome,
                    email,
                    senha,
                    tentativas,
                    ativo
                FROM USUARIO
                WHERE email = ?
            """, (email,))

            usuario = cursor.fetchone()

            if not usuario:
                flash('Email ou senha incorretos.')
                return redirect(url_for('login'))

            (
                id_usuario,
                nome,
                email_banco,
                senha_hash,
                tentativas,
                ativo
            ) = usuario

            if tentativas is None:
                tentativas = 0

            #BLOQUEAR APOS 3 TENTATIVAS
            if ativo == 0:
                flash('Usuario inativo ou bloqueado.')
                return redirect(url_for('login'))

            if usuario[6]>=3:
                flash("Usuário bloqueado após 3 tentativas")

                return redirect(url_for('login'))


            # VERIFICAR SENHA

            if bcrypt.check_password_hash(senha_hash, senha):

                session['id_usuario'] = id_usuario
                session['usuario_nome'] = nome
                session['usuario_email'] = email_banco

                cursor.execute("""
                    UPDATE USUARIO
                    SET tentativas = ?
                    WHERE id_usuario = ?
                """, (0, id_usuario))

                con.commit()

                flash('Login realizado com sucesso!')
                return redirect(url_for('index'))

            else:
                tentativas = usuario[6] + 1

                cursor.execute("""
                             UPDATE USUARIO
                             SET tentativas = ?, ativo = ?
                             WHERE id_usuario = ?
                                """, (tentativas, 0, id_usuario))

                con.commit()



            # SENHA INCORRETA

            if tentativas >= 3:
                flash('Usuario bloqueado apos 3 tentativas.')

            else:
                flash("Senha incorreta!")

            return redirect(url_for('login'))

        except Exception as erro:

            con.rollback()
            print('Erro no login:', erro)

            flash('Ocorreu um erro ao fazer login.')
            return redirect(url_for('login'))

        finally:
            cursor.close()

    return render_template('login.html')


# CADASTRO
# AS DUAS ROTAS UTILIZAM A MESMA FUNCAO.

@app.route(
    '/novo_usuario',
    methods=['GET', 'POST'],
    endpoint='novo_usuario'
)
@app.route(
    '/cadastro',
    methods=['GET', 'POST'],
    endpoint='cadastro'
)
def cadastrar_usuario():

    if request.method == 'GET':
        return render_template('cadastro.html')

    nome = request.form.get('nome')
    email = request.form.get('email')
    senha = request.form.get('senha')

    # VERIFICAR CAMPOS

    if not nome or not email or not senha:
        flash('Preencha todos os campos.')
        return redirect(url_for('cadastro'))

    # VERIFICAR SENHA FORTE

    if not senha_forte(senha):
        flash(
            'A senha deve ter pelo menos 8 caracteres, '
            'letra maiuscula, letra minuscula, numero '
            'e caractere especial.'
        )
        return redirect(url_for('cadastro'))

    cursor = con.cursor()

    try:

        # VERIFICAR EMAIL DUPLICADO

        cursor.execute("""
            SELECT id_usuario
            FROM USUARIO
            WHERE email = ?
        """, (email,))

        usuario_existente = cursor.fetchone()

        if usuario_existente:
            flash('Este email ja esta cadastrado.')
            return redirect(url_for('cadastro'))

        # CRIPTOGRAFAR SENHA

        senha_hash = bcrypt.generate_password_hash(
            senha
        ).decode('utf-8')

        # CADASTRAR USUARIO

        cursor.execute("""
            INSERT INTO USUARIO
            (
                nome,
                email,
                senha,
                tentativas,
                ativo,
                perfil
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            nome,
            email,
            senha_hash,
            0,
            1,
            PERFIL_ALUNO
        ))

        con.commit()

        flash('Usuario cadastrado com sucesso!')
        return redirect(url_for('login'))

    except Exception as erro:

        con.rollback()

        print('Erro ao cadastrar usuario:', erro)

        flash(f'Erro ao cadastrar usuario: {erro}')
        return redirect(url_for('cadastro'))

    finally:
        cursor.close()


# PAGINA PRINCIPAL

@app.route('/index')
def index():

    if 'id_usuario' not in session:
        flash('Faca login para acessar esta pagina.')
        return redirect(url_for('login'))

    return render_template('index.html')


# SAIR DA CONTA

@app.route('/logout')
def logout():

    session.clear()

    flash('Voce saiu da sua conta.')
    return redirect(url_for('login'))


# EXECUTAR APLICACAO

if __name__ == '__main__':
    app.run(debug=True)