from flask import Flask, render_template, request, redirect, url_for, flash, session
import fdb
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta_ativa_fitness'
bcrypt = Bcrypt(app)


# Conexão com o banco
host = 'localhost'
database = r'C:\Users\Aluno\Downloads\BancoDados\TRABALHOATFIT.FDB'
user = 'sysdba'
password = 'sysdba'

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)


# Landing page
@app.route('/')
def home():
    return render_template('landingpage.html')


# Função senha forte
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

    return (tem_maiuscula and tem_minuscula and tem_numero and tem_especial)


# Cadastrar novo usuário
@app.route('/novo_usuario', methods=['GET', 'POST'])
def novo_usuario():

    # Exibir formulário
    if request.method == 'GET':
        return render_template('novo_usuario.html')

    # Receber dados do formulário
    nome = request.form.get('nome', '').strip()
    email = request.form.get('email', '').strip()
    senha = request.form.get('senha', '')
    confirmar_senha = request.form.get('confirmar_senha', '')

    # Verificação campos preenchidos
    if not nome or not email or not senha or not confirmar_senha:

        flash('Preencha todos os campos.', 'erro')
        return redirect(url_for('novo_usuario'))

    # Verificação senhas iguais
    if senha != confirmar_senha:

        flash('As senhas não são iguais.', 'erro')
        return redirect(url_for('novo_usuario'))

    # Verificação senha forte
    if not senha_forte(senha):

        flash(
            'A senha deve ter pelo menos 8 caracteres, '
            'uma letra maiúscula, uma letra minúscula, '
            'um número e um caractere especial.', 'erro'
        )

        return redirect(url_for('novo_usuario'))

    cursor = con.cursor()

    try:

        # Verificação de e-mail já cadastrado
        cursor.execute(
            """
            SELECT id_usuario FROM USUARIO WHERE email = ?
            """,
            (email,)
        )

        usuario_existente = cursor.fetchone()

        if usuario_existente:

            flash('Este e-mail já está cadastrado.', 'erro')
            return redirect(url_for('novo_usuario'))

        # Criptografar a senha
        senha_hash = bcrypt.generate_password_hash(
            senha
        ).decode('utf-8')

        # Cadastrar usuário
        cursor.execute(
            """
            INSERT INTO USUARIO(nome, email, senha, tentativas, ativo)
            VALUES (?, ?, ?, ?, ?)
            """,
            (nome, email, senha_hash, 0, 1)
        )

        # Salvar no banco
        con.commit()

        flash('Usuário cadastrado com sucesso!', 'sucesso')

        return redirect(url_for('login'))

    # Tratar erros
    except Exception as e:

        con.rollback()

        flash(f'Erro ao cadastrar usuário: {e}', 'erro')

        return redirect(url_for('novo_usuario'))

    # Fechar o cursor
    finally:
        cursor.close()


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():

    # Se o formulário foi enviado
    if request.method == 'POST':

        # Pegar os dados enviados pelo formulário
        email = request.form.get('email')
        senha = request.form.get('senha')

        # Verificar se os campos foram preenchidos
        if not email or not senha:

            flash('Preencha o email e a senha.', 'erro')

            return redirect(url_for('login'))

        cursor = con.cursor()

        try:

            # Buscar usuário pelo e-mail
            cursor.execute(
                """
                SELECT
                    id_usuario,
                    nome,
                    email,
                    senha,
                    tentativas,
                    ativo
                FROM USUARIO
                WHERE email = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            # Usuário não encontrado
            if not usuario:

                flash('Email ou senha incorretos.', 'erro')
                return redirect(url_for('login'))

            # Organizar dados do usuário
            (
                id_usuario,
                nome,
                email_banco,
                senha_hash,
                tentativas,
                ativo
            ) = usuario

            # Caso tentativas esteja NULL no banco
            if tentativas is None:
                tentativas = 0

            # Verificar se o usuário está ativo
            if ativo == 0:

                flash('Usuário inativo ou bloqueado.', 'erro')
                return redirect(url_for('login'))

            # Verificar senha
            if bcrypt.check_password_hash(senha_hash, senha):

                # Guardar os dados na sessão
                session['id_usuario'] = id_usuario
                session['usuario_nome'] = nome
                session['usuario_email'] = email_banco

                # Zerar as tentativas
                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET tentativas = ?
                    WHERE id_usuario = ?
                    """,
                    (0, id_usuario)
                )

                con.commit()

                flash('Login realizado com sucesso!', 'sucesso')

                return redirect(url_for('index'))

            # Senha incorreta
            tentativas += 1

            # Bloquear após 3 tentativas
            if tentativas >= 3:

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET tentativas = ?, ativo = ?
                    WHERE id_usuario = ?
                    """,
                    (tentativas, 0, id_usuario)
                )

                con.commit()

                flash('Usuário bloqueado após 3 tentativas.', 'erro')

                return redirect(url_for('login'))

            # Atualizar tentativas
            cursor.execute(
                """
                UPDATE USUARIO
                SET tentativas = ?
                WHERE id_usuario = ?
                """,
                (tentativas, id_usuario)
            )

            con.commit()

            flash(
                f'Email ou senha incorretos. '
                f'Tentativa {tentativas} de 3.', 'erro'
            )

            return redirect(url_for('login'))

        # Erro no banco ou no login
        except Exception as e:

            con.rollback()

            flash(f'Ocorreu um erro no login: {e}', 'erro')

            return redirect(url_for('login'))

        finally:
            cursor.close()

    return render_template('login.html')


# Início / Dashboard
@app.route('/inicio')
def index():

    # Verificar se o usuário está logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Pegar o nome do usuário
    nome = session['usuario_nome']

    return render_template('dashboard.html', nome=nome)


# Editar perfil

@app.route('/editar_perfil', methods=['GET', 'POST'])
def editar_perfil():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()

    try:
        if request.method == 'POST':
            nome = request.form['nome'].strip()
            email = request.form['email'].strip()
            senha = request.form.get('senha', '')
            confirmar_senha = request.form.get('confirmar_senha', '')

            # Verificar se nome e email foram preenchidos
            if not nome or not email:
                flash('Preencha o nome e o e-mail.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Verificar se as senhas são iguais
            if senha != confirmar_senha:
                flash('As senhas não são iguais.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Verificar se o email já pertence a outro usuário
            cursor.execute(
                'SELECT id_usuario FROM USUARIO WHERE email = ? AND id_usuario <> ?',
                (email, id_usuario)
            )

            if cursor.fetchone():
                flash('Este e-mail já está cadastrado.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Atualizar os dados e criptografar a nova senha
            if senha:
                senha_hash = bcrypt.generate_password_hash(
                    senha
                ).decode('utf-8')

                cursor.execute(
                    'UPDATE USUARIO SET nome = ?, email = ?, senha = ? WHERE id_usuario = ?',
                    (nome, email, senha_hash, id_usuario)
                )

            else:
                cursor.execute(
                    'UPDATE USUARIO SET nome = ?, email = ? WHERE id_usuario = ?',
                    (nome, email, id_usuario)
                )

            # Salvar as alterações no banco
            con.commit()

            # Atualizar os dados da sessão
            session['usuario_nome'] = nome
            session['usuario_email'] = email

            flash('Perfil atualizado com sucesso!', 'sucesso')
            return redirect(url_for('editar_perfil'))

        # Buscar os dados atuais do usuário
        cursor.execute(
            'SELECT nome, email FROM USUARIO WHERE id_usuario = ?',
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if usuario is None:
            session.clear()
            return redirect(url_for('login'))

        nome = usuario[0]
        email = usuario[1]

        return render_template(
            'editar_perfil.html',
            nome=nome,
            email=email
        )

    except Exception:
        con.rollback()
        flash('Não foi possível atualizar o perfil.', 'erro')
        return redirect(url_for('editar_perfil'))

    finally:
        cursor.close()



# Logout
@app.route('/logout')
def logout():

    # Apagar os dados da sessão
    session.clear()

    flash('Você saiu da sua conta, com sucesso!', 'sucesso')

    return redirect(url_for('login'))


#Grade de aulas
@app.route('/grade_de_aulas', methods=['GET', 'POST'])
def grade_de_aulas():
    return render_template('grade_de_aulas.html')


#Dashboard administrador
@app.route('/dashboard_administrador', methods=['GET', 'POST'])
def dashboard_administrador():
    return render_template('dashboard_administrador.html')


if __name__ == '__main__':
    app.run(debug=True)