0.先创建虚拟环境 

$ python -m venv venv

1.首先激活虚拟环境，需使用以下命令：

$ source venv/bin/activate

terminal会显示为(venv) $ _

如果你使用的是Microsoft Windows命令提示符窗口，则激活命令稍有不同：

$ venv\Scripts\activate

(venv) $ _

然后根据requirements.txt新建虚拟环境

$ pip install -r requirements.txt


2.所有包安装完毕后运行flask

$ flask run

在浏览器内输入localhost:5000即可打开网页

3.配置文件存放在config.py内。

4.flask环境变量存放在.flaskenv中。

5.激活虚拟环境后运行flask shell可以进入交互模式调试。


有两个我设置的测试账号：

username: test

email: test@example.com

password: 123

---------------------------
username: test1

email: test1@example.com

password: 123


