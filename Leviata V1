Evolução da arquitetura
Conforme desenvolvi o Leviata, comecei a perceber algumas limitações na estrutura inicial(que estava bem...torta...) 

Sempre que adicionava um módulo novo, precisava alterar a CLI para conseguir executá-lo. Isso me levou a pensar:
A CLI realmente precisa conhecer cada módulo(não!! isso só me deu mais trabalhao aleatorio mas eu não sabia disso na época... bem o importante foi que ele funcionou como ferramenta)

A resposta foi não(obvio)

A CLI poderia cuidar do parsing dos comandos, enquanto um Command Router organizaria a execução dos módulos e suas funções

A partir disso, a arquitetura começou a tomar esta forma:
CLI → Command Router → [Módulo | Pipeline] → Result/Data Store → Terminal/JSON → Comparator → Diferenças

Também percebi que módulos poderiam ser executados individualmente ou combinados em pipelines, e que dados já obtidos poderiam ser reutilizados em outras etapas.

A ideia do Result/Data Store surgiu justamente para isso, além de permitir guardar resultados de diferentes execuções para comparação posterior.

O Leviata original:
O Leviata original era bem mais simples. Conforme fui usando e modificando o projeto, encontrei problemas que não teria percebido apenas planejando.
Por isso, vejo aquela versão como uma PoC/versão experimental(ferramenta!!). O V1 é uma tentativa de reorganizar o projeto a partir do que aprendi com ela.

Como cheguei nisso:
O desenvolvimento acabou seguindo um processo simples(caotico... mas agora organizado):
problema → hipótese → teste → erro/acerto → novas possibilidades → comparação → nova tentativa
O Leviata V1 nasceu desse processo(que confesso que é o meu padrão... fazer o que...).

Nota da criadora
Tá, agora vem uma das partes que mais me fez repensar a arquitetura.

Eu não quero criar 300 arquivos chamados modulo1, modulo2, modulo3... e também comecei a pensar no que aconteceria se um módulo desse errado e acabasse afetando outro. Como eu saberia qual foi o erro primário? Isso rapidamente deixaria de ser sustentável 💀.

Além disso, algumas coisas que eu queria testar envolviam recursos que não são tão tranquilos de lidar diretamente no Windows, especialmente quando comecei a pensar em raw sockets. O Windows adoraria comer meu fígado por causa disso... (sério.. o carinha chato pra coisas que são mais baixas) 

Então fui pesquisar e acabei voltando para uma coisa que eu já conhecia, mas não usava há bastante tempo: WSL.
Instalei, comecei a testar novamente e acabei aprendendo bastante coisa no processo. Depois fui estudar sobre containers e percebi que eles poderiam resolver parte do problema dos módulos, permitindo isolamento entre eles e facilitando testes separados.

Daí entrou o Docker, principalmente para facilitar o gerenciamento desses containers.

Agora falta colocar a mão na massa.

O único pequeno detalhe é que minha rotina atualmente está funcionando igual ao Windows em um PC com 4 GB de RAM: quase não sobra espaço para nada. 😔

Mas seguirei firme.
