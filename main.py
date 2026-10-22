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

    nome = request.form['nome'].strip()
    print(nome)
    email = request.form['email'].strip()
    senha = request.form['senha']
    confirmar_senha = request.form['confirmar_senha']


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
        email = request.form['email'].strip()
        senha = request.form['senha']

        # Verificar se os campos foram preenchidos
        if not email or not senha:
            flash('Preencha o email e a senha.', 'erro')
            return redirect(url_for('login'))


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

                flash('Login realizado com sucesso!', 'sucesso')



            else:
                if tipo != 0:
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
                else:
                    flash(f'Email ou senha incorretos. ')
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
        print(tipo)
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

            nome = request.form('nome').strip()
            email = request.form('email').strip()
            senha = request.form('senha')
            confirmar_senha = request.form('confirmar_senha')

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

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        cursor.execute("""SELECT id_aula, horario, capacidade, id_modalidade, id_usuario
                       FROM AULA 
                       ORDER BY DIA, HORARIO""")
        aulas = cursor.fetchall()

        return render_template(
            'grade_de_aulas.html',
            nome=session['usuario_nome'],
            tipo=session['tipo_usuario'],
            id_usuario=session['id_usuario'],
            aulas=aulas
        )

    except Exception as e:
        print('Erro ao carregar aulas:', e)
        flash('Erro ao carregar as aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    finally:
        cursor.close()


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


# Cadastrar aula
@app.route('/cadastrar_aula', methods=['GET', 'POST'])
def cadastrar_aula():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    # Somente o administrador pode cadastrar aulas
    if session['tipo_usuario'] != 0:
        flash('Você não tem permissão para cadastrar aulas.', 'erro')
        return redirect(url_for('redirecionar'))

    if request.method == 'POST':

        nome = request.form['nome'].strip()
        descricao = request.form['descricao'].strip()
        dias = request.form.getlist('dia[]')
        horario = request.form['horario']
        capacidade = request.form['capacidade']
        professor = request.form['professor']

        # Verificar os campos
        if not nome or not horario or not capacidade or not professor or not dias:
            flash('Preencha todos os campos obrigatórios.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        # Verificar a capacidade
        try:
            capacidade = int(capacidade)

            if capacidade < 1 or capacidade > 18:
                flash('A capacidade deve ser entre 1 e 18 pessoas.', 'erro')
                return redirect(url_for('cadastrar_aula'))

        except ValueError:
            flash('Informe uma capacidade válida.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        cursor = con.cursor()

        try:
            # Verificar cada dia selecionado
            for dia in dias:
                cursor.execute("""
                    SELECT ID_AULA
                    FROM AULA
                    WHERE NOME = ? AND DIA = ? AND HORARIO = ?
                """, (nome, dia, horario))

                if cursor.fetchone():
                    flash(
                        'Essa aula já está cadastrada nesse dia e horário.',
                        'erro'
                    )
                    return redirect(url_for('cadastrar_aula'))

            # Salvar a aula no banco
            for dia in dias:

                cursor.execute("""
                    INSERT INTO AULA
                    (NOME, DESCRICAO, DIA, HORARIO, CAPACIDADE, PROFESSOR)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    nome,
                    descricao,
                    dia,
                    horario,
                    capacidade,
                    professor
                ))

            con.commit()

            flash('Aula cadastrada com sucesso!', 'sucesso')
            return redirect(url_for('grade_de_aulas'))

        except Exception as e:
            con.rollback()
            print('Erro ao cadastrar aula:', e)
            flash('Não foi possível cadastrar a aula.', 'erro')
            return redirect(url_for('cadastrar_aula'))

        finally:
            cursor.close()

    return render_template('cadastrar_aula.html')




if __name__ == '__main__':
    app.run(debug=True)
