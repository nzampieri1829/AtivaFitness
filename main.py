from flask import Flask, render_template, request, redirect, url_for, flash, session
import fdb
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave_secreta_ativa_fitness'
bcrypt = Bcrypt(app)


# Conexao com o banco de dados
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


# Pagina inicial
@app.route('/')
def home():
    return render_template('landingpage.html')


# Funcao para verificar se a senha e forte
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


# Cadastrar novo usuario (somente aluno)
@app.route('/novo_usuario', methods=['GET', 'POST'])
def novo_usuario():

    # cadastro aluno
    tipo = 1

    if request.method == 'GET':
        return render_template('novo_usuario.html')

    nome = request.form.get('nome', '').strip()
    email = request.form.get('email', '').strip()
    senha = request.form.get('senha', '')
    confirmar_senha = request.form.get('confirmar_senha', '')


    # verificar campos preenchidos
    if not nome or not email or not senha or not confirmar_senha:
        flash('Preencha todos os campos.', 'erro')
        return redirect(url_for('novo_usuario'))

    # verificar senha igual
    if senha != confirmar_senha:
        flash('As senhas nao sao iguais.', 'erro')
        return redirect(url_for('novo_usuario'))

    #  senha forte
    if not senha_forte(senha):
        flash(
            'A senha deve ter pelo menos 8 caracteres, '
            'uma letra maiuscula, uma letra minuscula, '
            'um numero e um caractere especial.',
            'erro'
        )
        return redirect(url_for('novo_usuario'))

    cursor = con.cursor()

    try:

        # Verificar email cadastrado
        cursor.execute(
            """
            SELECT id_usuario
            FROM USUARIO
            WHERE email = ?
            """,
            (email,)
        )

        usuario_existente = cursor.fetchone()

        if usuario_existente:
            flash('Este e-mail ja esta cadastrado.', 'erro')
            return redirect(url_for('novo_usuario'))

        # Criptografar a senha
        senha_hash = bcrypt.generate_password_hash(
            senha
        ).decode('utf-8')

        # Cadastrar o usuario como aluno (tipo 1)
        cursor.execute(
            """
            INSERT INTO USUARIO
                (nome, email, senha, tentativas, ativo, tipo)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (nome, email, senha_hash, 0, 1, tipo)
        )

        con.commit()

        flash('Usuario cadastrado com sucesso!', 'sucesso')
        return redirect(url_for('login'))

    except Exception as e:
        con.rollback()
        print('Erro ao cadastrar usuario:', e)
        flash('Erro ao cadastrar usuario.', 'erro')
        return redirect(url_for('novo_usuario'))

    finally:
        cursor.close()



# Login para aluno, administrador e professor
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        # Receber os dados do formulario
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')

        # Verificar se os campos foram preenchidos
        if not email or not senha:
            flash('Preencha o email e a senha.', 'erro')
            return redirect(url_for('login'))

        # Login do administrador
        if email == "laisadm@gmail.com" and senha == "Laisadm#123":

            session['id_usuario'] = 0
            session['usuario_nome'] = 'Administrador'
            session['usuario_email'] = email
            session['tipo_usuario'] = 0

            return redirect(url_for('dashboard_administrador'))

        cursor = con.cursor()

        try:
            # Buscar o usuario pelo email
            cursor.execute(
                """
                SELECT
                    id_usuario,
                    nome,
                    email,
                    senha,
                    tentativas,
                    ativo,
                    tipo
                FROM USUARIO
                WHERE email = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            # Verificar se o usuario existe
            if not usuario:
                flash('Email ou senha incorretos.', 'erro')
                return redirect(url_for('login'))

            # Separar os dados do usuario
            (
                id_usuario,
                nome,
                email_banco,
                senha_hash,
                tentativas,
                ativo,
                tipo
            ) = usuario

            if tentativas is None:
                tentativas = 0

            # Verificar se a conta esta ativa
            if ativo == 0:
                flash('Usuario inativo ou bloqueado.', 'erro')
                return redirect(url_for('login'))

            # Verificar a senha
            if bcrypt.check_password_hash(senha_hash, senha):

                # Verificar se o tipo e valido
                if tipo not in (0, 1, 2):
                    flash('Tipo de usuario invalido.', 'erro')
                    return redirect(url_for('login'))

                # Guardar os dados na sessao
                session['id_usuario'] = id_usuario
                session['usuario_nome'] = nome
                session['usuario_email'] = email_banco
                session['tipo_usuario'] = tipo

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

                # ALUNO: tipo 1
                if tipo == 1:
                    return redirect(url_for('index'))

                # ADMINISTRADOR: tipo 0
                elif tipo == 0:
                    return redirect(
                        url_for('dashboard_administrador')
                    )

                # PROFESSOR: tipo 2
                elif tipo == 2:
                    return redirect(url_for('grade_de_aulas'))

            else:
                # Senha incorreta
                tentativas += 1

                # Bloquear depois de 3 tentativas
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

                    flash(
                        'Usuario bloqueado apos 3 tentativas.',
                        'erro'
                    )

                    return redirect(url_for('login'))

                # Atualizar o numero de tentativas
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
                    f'Tentativa {tentativas} de 3.',
                    'erro'
                )

                return redirect(url_for('login'))

        except Exception as e:
            con.rollback()
            print('Erro no login:', e)
            flash('Ocorreu um erro no login.', 'erro')
            return redirect(url_for('login'))

        finally:
            cursor.close()

    return render_template('login.html')


# Dashboard do aluno
@app.route('/inicio')
def index():

    # Verificar se esta logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Verificar se é aluno
    if session.get('tipo_usuario') != 1:
        flash('Voce não tem permissao para acessar esta pagina.', 'erro')
        return redirect(url_for('redirecionar'))

    nome = session['usuario_nome']

    return render_template(
        'dashboard.html',
        nome=nome
    )


# Dashboard do administrador
@app.route('/dashboard_administrador')
def dashboard_administrador():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    if session.get('tipo_usuario') != 0:
        flash('Voce nao tem permissao para acessar esta pagina.', 'erro')
        return redirect(url_for('redirecionar'))

    nome = session.get('usuario_nome')

    return render_template(
        'dashboard_administrador.html',
        nome=nome
    )
# Redirecionar conforme o tipo de usuario
@app.route('/redirecionar')
def redirecionar():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session.get('tipo_usuario')

    if tipo == 1:
        return redirect(url_for('index'))

    elif tipo == 0:
        return redirect(url_for('dashboard_administrador'))

    elif tipo == 2:
        return redirect(url_for('grade_de_aulas'))

    else:
        flash('Tipo de usuario invalido.', 'erro')
        return redirect(url_for('login'))


# Editar perfil
@app.route('/editar_perfil', methods=['GET', 'POST'])
def editar_perfil():

    # Verificar se esta logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Verificar se o tipo e valido
    tipo = session.get('tipo_usuario')

    if tipo != 0 and tipo != 1 and tipo != 2:
        return redirect(url_for('login'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()

    try:

        if request.method == 'POST':

            nome = request.form.get('nome', '').strip()
            email = request.form.get('email', '').strip()
            senha = request.form.get('senha', '')
            confirmar_senha = request.form.get(
                'confirmar_senha', ''
            )

            # Verificar nome e email
            if not nome or not email:
                flash('Preencha o nome e o e-mail.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Verificar se as senhas sao iguais
            if senha != confirmar_senha:
                flash('As senhas nao sao iguais.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Verificar se a nova senha e forte
            if senha and not senha_forte(senha):
                flash(
                    'A senha deve ter pelo menos 8 caracteres, '
                    'uma letra maiuscula, uma letra minuscula, '
                    'um numero e um caractere especial.',
                    'erro'
                )
                return redirect(url_for('editar_perfil'))

            # Verificar se o email pertence a outro usuario
            cursor.execute(
                """
                SELECT id_usuario
                FROM USUARIO
                WHERE email = ? AND id_usuario <> ?
                """,
                (email, id_usuario)
            )

            if cursor.fetchone():
                flash('Este e-mail ja esta cadastrado.', 'erro')
                return redirect(url_for('editar_perfil'))

            # Atualizar nome, email e senha
            if senha:

                senha_hash = bcrypt.generate_password_hash(
                    senha
                ).decode('utf-8')

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET nome = ?, email = ?, senha = ?
                    WHERE id_usuario = ?
                    """,
                    (nome, email, senha_hash, id_usuario)
                )

            else:

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET nome = ?, email = ?
                    WHERE id_usuario = ?
                    """,
                    (nome, email, id_usuario)
                )

            con.commit()

            # Atualizar os dados da sessao
            session['usuario_nome'] = nome
            session['usuario_email'] = email

            flash('Perfil atualizado com sucesso!', 'sucesso')
            return redirect(url_for('editar_perfil'))

        # Buscar os dados do usuario logado
        cursor.execute(
            """
            SELECT nome, email
            FROM USUARIO
            WHERE id_usuario = ?
            """,
            (id_usuario,)
        )

        usuario = cursor.fetchone()

        if usuario is None:
            return redirect(url_for('login'))

        nome = usuario[0]
        email = usuario[1]

        return render_template(
            'editar_perfil.html',
            nome=nome,
            email=email,
            tipo=tipo,
            id_usuario=id_usuario
        )

    except Exception as e:
        con.rollback()
        print('Erro ao editar perfil:', e)
        flash('Nao foi possivel atualizar o perfil.', 'erro')
        return redirect(url_for('editar_perfil'))

    finally:
        cursor.close()


# Logout
@app.route('/logout')
def logout():


    flash('Voce saiu da sua conta com sucesso!', 'sucesso')

    return redirect(url_for('login'))


# Grade de aulas
@app.route('/grade_de_aulas', methods=['GET', 'POST'])
def grade_de_aulas():

    # Verificar se esta logado
    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session['tipo_usuario']

    # Permitir somente os tipos 0, 1 e 2
    if tipo != 0 and tipo != 1 and tipo != 2:
        return redirect(url_for('login'))

    nome = session['usuario_nome']
    id_usuario = session['id_usuario']

    return render_template(
        'grade_de_aulas.html',
        nome=nome,
        tipo=tipo,
        id_usuario=id_usuario
    )


# Cadastrar aula
#administrador (0) professor (2)
@app.route('/cadastrar_aula', methods=['GET', 'POST'])
def cadastrar_aula():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session.get('tipo_usuario')

    if tipo != 0 and tipo != 2:
        flash('Voce nao tem permissao para cadastrar aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    if request.method == 'POST':
        flash(
            'O salvamento das aulas precisa ser implementado '
            'conforme as tabelas do banco.',
            'erro'
        )
        return redirect(url_for('cadastrar_aula'))

    return render_template(
        'cadastrar_aula.html',
        tipo=tipo,
        id_usuario=session['id_usuario']
    )


# Editar aula
# administrador (0)  professor (2)
@app.route('/editar_aula/<int:id_aula>', methods=['GET', 'POST'])
def editar_aula(id_aula):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    tipo = session.get('tipo_usuario')

    if tipo != 0 and tipo != 2:
        flash('Voce nao tem permissao para editar aulas.', 'erro')
        return redirect(url_for('redirecionar'))



    return render_template(
        'editar_aula.html',
        id_aula=id_aula,
        tipo=tipo,
        id_usuario=session['id_usuario']
    )


if __name__ == '__main__':
    app.run(debug=True)
