"""
@File    ：app.py.py
@Author  ：TXL
@Date    ：2022/10/16 13:42 
"""
# -*- coding: UTF-8 -*-

from flask import Flask, render_template, request, abort, session, redirect, url_for, jsonify

from mapper.Register import register_sql
from mapper.Login import login_sql
from bean.static import *
from util.Hack_Pot import get_hacker
from util.Random_Str import get_random_str
from bean.MyThread import MyThread

app = Flask(
    __name__,
    static_folder="st1",
    template_folder="st2",
)
app.secret_key = 'why would I tell you my secret key?'


@app.route("/", methods=['GET'])
def main_page():
    if session.get(USER_INFORMATION) is None:
        # 未登录请先登录
        return redirect("/login/p")
    # print(request.args.get("child"))
    data = {
        "page": "true",
        "container": "Welcome Here!",
        "msg": "/st1/welcome.html"
    }

    if request.args.get("child") is not None:
        data["msg"] = request.args.get("child")
    # print(data)
    return render_template("html/main.html", data=data)


@app.route("/form/scan/<int:host_type>/<int:scan_type>", methods=['GET'])
def scan_form(host_type, scan_type):
    """
    通过该路由引出所有希望用户填入设置的表单
    :param host_type:
    :param scan_type:
    :return:form_frame.html，在这中间通过Jinja进行传参
    """
    if not 3 > host_type > 0 or not 4 > scan_type > 0:
        abort(500)
    if session.get(USER_INFORMATION) is None:
        return redirect("/login/p")
    data = {}
    if host_type == 1:
        # 主机扫描
        data.update({
            "methods": "post",
            "form_list": [
                ["主机地址*", FORM_HOSTS, "请写入主机地址或域名"]
            ],
        })
        if scan_type == 1:
            # scapy扫描
            data.update({
                "scan_type": "主机 Scapy ",
                "action": "/scan/host-scapy/",
            })
            return render_template("html/scan/form_frame.html", data=data)
        elif scan_type == 2:
            # nmap扫描
            data.update({
                "scan_type": "主机 Nmap ",
                "action": "/scan/host-nmap/",
            })
            return render_template("html/scan/form_frame.html", data=data)
        elif scan_type == 3:
            # socket扫描
            data.update({
                "scan_type": "主机 Socket ",
                "action": "/scan/host-socket/",
            })
            return render_template("html/scan/form_frame.html", data=data)
    elif host_type == 2:
        # 端口扫描
        data.update({
            "methods": "post",
            "form_list": [
                ["主机地址*", FORM_HOSTS, "请写入主机地址或域名"],
                ["端口号*", FORM_PORTS, "可写入形式：22-80、22,80、80"],
            ],
        })
        if scan_type == 1:
            # scapy扫描
            data.update({
                "scan_type": "端口 Scapy ",
                "action": "/scanports-scapy/",
            })
            return render_template("html/scan/form_frame.html", data=data)
        elif scan_type == 2:
            # nmap扫描
            data.update({
                "scan_type": "端口 Nmap ",
                "action": "/scan/ports-nmap/",
            })
            data["form_list"].append(["扫描模式", FOR_NMAP, "本项为可选项，默认扫描模式为-sV"])
            return render_template("html/scan/form_frame.html", data=data)
        elif scan_type == 3:
            # socket扫描
            data.update({
                "scan_type": "端口 Socket ",
                "action": "/scan/ports-socket/",
            })
            return render_template("html/scan/form_frame.html", data=data)
    return "开发中，敬请期待<script>alert(1)</script>"


@app.route("/scan/<string:type_>-<string:tool>/", methods=['POST'])
def scan_scan(type_, tool):
    if session.get(USER_INFORMATION) is None:
        # 未登录请先登录
        return redirect("/login/p")
    if type_ == "host":
        # 主机存活扫描
        hosts = request.form.get(FORM_HOSTS)
        dns = hosts.isalpha()
        if tool == "scapy":
            from util.Scan_Time import scapy_scan_host
            t = MyThread(scapy_scan_host, (session.get(USER_INFORMATION)[0], hosts, dns), scapy_scan_host.__name__)
            t.start()
            return redirect("/st1/waiting.html")
        elif tool == "nmap":
            from util.Scan_Time import nmap_scan_hosts
            t = MyThread(nmap_scan_hosts, (session.get(USER_INFORMATION)[0], hosts), nmap_scan_hosts.__name__)
            t.start()
            return redirect("/st1/waiting.html")
        elif tool == "socket":
            return redirect("/st1/waiting.html")
        else:
            abort(500)
            return "Error"
    elif type_ == "ports":
        hosts = request.form.get(FORM_HOSTS)
        ports = request.form.get(FORM_PORTS)
        dns = hosts.isalpha()
        if tool == "scapy":
            from util.Scan_Time import scapy_scan_ports
            t = MyThread(scapy_scan_ports, (session.get(USER_INFORMATION)[0], hosts, ports, dns),
                         scapy_scan_ports.__name__)
            t.start()
            return redirect("/st1/waiting.html")
        elif tool == "nmap":
            from util.Scan_Time import nmap_scan_ports
            scan_type = request.form.get(FOR_NMAP)
            if scan_type is None: "-sV"
            t = MyThread(nmap_scan_ports, (session.get(USER_INFORMATION)[0], hosts, ports, scan_type),
                         nmap_scan_ports.__name__)
            t.start()
            return redirect("/st1/waiting.html")
        elif tool == "socket":
            return redirect("/st1/waiting.html")
        else:
            abort(500)
            return "Error"
    else:
        return "<script>研发中，敬请期待</script>"


@app.route("/myscan", methods=['GET'])
def myscan():
    if session.get(USER_INFORMATION) is None:
        # 未登录请先登录
        return redirect("/login/p")
    id_value = session.get(USER_INFORMATION)[0]
    username = session.get(USER_INFORMATION)[1]
    level = session.get(USER_INFORMATION)[2]
    data = {
        "id": id_value,
        "username": username,
        "level": str(level),
        "form": [
            ["扫描id", SCAN_ID, "了解就写上，不了解则置空"],
            ["请求方式", False, SCAN_BYWAY],  # 此处应为复选框
            ["扫描主机对象", SCAN_HOSTS, "本字段支持模糊查询"],
            ["扫描端口", SCAN_PORTS, "如需模糊查询请以类似“%8%”的形式输入"],
            ["错误码", SCAN_ERRORCODE, "扫描出错的情况下，错误码会出现，不了解可置空"]
        ]
    }
    return render_template("html/scan/table_frame.html", data=data)


@app.route('/myscan/select', methods=['POST'])
def myscan_select():
    if session.get(USER_INFORMATION) is None:
        # 未登录请先登录
        return redirect("/login/p")
    id_value = session.get(USER_INFORMATION)[0]
    username = session.get(USER_INFORMATION)[1]
    type_ = request.form.get("type_")
    scan_id = request.form.get(SCAN_ID)
    scan_byway = request.form.get(SCAN_BYWAY)
    scan_hosts = request.form.get(SCAN_HOSTS)
    scan_ports = request.form.get(SCAN_PORTS)
    scan_errorcode = request.form.get(SCAN_ERRORCODE)

    if scan_id == "": scan_id = None
    if scan_hosts == "": scan_hosts = None
    if scan_ports == "": scan_ports = None
    if scan_errorcode == "": scan_errorcode = None
    # print(scan_hosts)

    if type_ == "11":
        # 主机扫描
        from mapper.Select_By import by_something_host
        from bean.My_Scan_Host import my_scan_host
        ends = by_something_host(user_id=id_value, scan_id=scan_id, byway=scan_byway, hosts_=scan_hosts,
                                 errorcode=scan_errorcode)
        myscans_host = []
        # print("------------------")
        # print(ends)
        for end in ends:
            # print("*****************")
            myscan_host = my_scan_host(scan_time=end[0], scan_id=end[1], user_id=id_value, username=username,
                                       byway=end[3], hosts=end[4], end=end[5], errorcode=end[6])
            myscans_host.append(myscan_host.get_json())
        return jsonify({"a": "a", "TableList": myscans_host})
    elif type_ == "22":
        # 端口扫描
        from mapper.Select_By import by_something_port
        from bean.My_Scan_Ports import my_scan_ports
        ends = by_something_port(user_id=id_value, scan_id=scan_id, byway=scan_byway, hosts_=scan_hosts,
                                 ports=scan_ports, errorcode=scan_errorcode)
        myscans_port = []
        for end in ends:
            # print(end[7])
            myscan_port = my_scan_ports(scan_time=end[0], scan_id=end[1], user_id=id_value, username=username,
                                        byway=end[3], hosts=end[4], end=end[6], ports=end[5], errorcode=end[7])
            myscans_port.append(myscan_port.get_json())
        return jsonify({"a": "b", "TableList": myscans_port})
    else:
        abort(500)
        return ""

    # print(end)

    # data = {
    #     "id": id_value,
    #     "username": session.get(USER_INFORMATION)[1],
    #     "level": str(session.get(USER_INFORMATION)[2]),
    #     "form": [
    #         ["扫描id", SCAN_ID, "了解就写上，不了解则置空"],
    #         ["请求方式", False, SCAN_BYWAY],  # 此处应为复选框
    #         ["扫描主机对象", SCAN_HOSTS, "本字段支持模糊查询"],
    #         ["扫描端口", SCAN_PORTS, "如需模糊查询请以类似“%8%”的形式输入"],
    #         ["错误码", SCAN_ERRORCODE, "扫描出错的情况下，错误码会出现，不了解可置空"]
    #     ]
    # }
    # return render_template("html/scan/table_frame.html", data=data)


@app.route('/myself', methods=['GET', 'POST'])
def myself():
    if session.get(USER_INFORMATION) is None:
        # 未登录请先登录
        return redirect("/login/p")
    id_value = session.get(USER_INFORMATION)[0]
    if request.method == 'GET':
        username = session.get(USER_INFORMATION)[1]
        level = session.get(USER_INFORMATION)[2]
        data = {
            "methods": "get",
            "list": [
                ["权限等级", level],
                ["用户id", id_value]
            ],
            "form_list": [
                [True, "用户名", USER_NAME, username],
                [False, "重置密码", USER_NEW_PASSWD, "如需重置密码请在这里输入新密码，如不需要请留空"],
                [False, "重复密码", USER_REP_PASSWD, "如需重置密码请在这里重复输入新密码，如不需要请留空"]
            ],
        }
        return render_template("html/myself.html", data=data)
    else:

        pass


@app.route("/login/<string:random_str>", methods=['GET', 'POST'])
def login(random_str):
    if session.get(USER_INFORMATION) is not None:
        return redirect("/")
    if request.method == 'GET':
        session[RANDOM_STR_TOKEN] = get_random_str(RAN_TOKEN_LEN)
        session[LOGIN_FAIL_NUM] = 0
        data = {
            "random_str": session.get(RANDOM_STR_TOKEN),
            "alert": "false"
        }
        if random_str == "warning":
            data["alert"] = "true"
            data.update({"msg": "就特么你小子是吧？(´ω｀★)"})
        elif random_str == "warning_":
            data["alert"] = "true"
            data.update({"msg": "亲，不要乱动数据包哦！(´ω｀★)"})
        elif random_str == "passwderror":
            session[LOGIN_FAIL_NUM] += 1
            data["alert"] = "true"
            if session.get("login_error_time") < 3:
                data.update({"msg": "亲，用户名或密码输错了呢，想一想再试试好不好？(´ω｀★)"})
            elif 10 > session.get("login_error_time") >= 5:
                data.update({"msg": "亲，用户名或密码输错的次数，有点多了呢？Σ( ° △ °|||)︴"})
            else:
                # 本来是考虑着在这边做个防止爆破程序爆破所以准备做个限流的，但是这个课题就留到后边吧2333
                data.update({"msg": "麻烦亲先冷静一下，咱们等会儿再试试好不好？w(ﾟДﾟ)w"})
        elif random_str == "success":
            id_value = session.get(USER_INFORMATION)[0]
            username = session.get(USER_INFORMATION)[1]
            level = session.get(USER_INFORMATION)[2]
            data["alert"] = "true"
            data.update({"msg": "登陆成功了哎！好耶！\\n您的ID为：" + id_value + "\\n您的用户名为：" + username + "\\n您的权限等级为：" + str(level),
                         "target": "/"})
            session[LOGIN_FAIL_NUM] = 0

            return render_template("html/tools/jump.html", data=data)
        return render_template("html/login.html", data=data)
    if session.get(RANDOM_STR_TOKEN) != random_str:
        # Situation1:The hacker changed the token_str.
        get_hacker(request)  # 抓进罐子里。key: HvRRjcgDbeGDEd4EuZeEaiJKC6P74p7LBg9Tv8rp6R
        session[RANDOM_STR_TOKEN] = None
        return redirect("/login/warning")
    username = request.form.get('username')
    password = request.form.get('password')
    if username is None or password is None or len(random_str) < RAN_TOKEN_LEN - 1:
        get_hacker(request)  # 抓进罐子里。key: HvRRjcgDbeGDEd4EuZeEaiJKC6P74p7LBg9Tv8rp6R
        session[RANDOM_STR_TOKEN] = None
        return redirect("/login/warning_")
    session[RANDOM_STR_TOKEN] = None
    login_status = login_sql(username=username, passwd_base=password, random=random_str)
    if isinstance(login_status, int):
        if login_status == USERNAME_NOT_EXIST or login_status == PASSWD_ERROR:
            return redirect("/login/passwderror")
    user_id, level_num = login_status
    session[USER_INFORMATION] = [user_id, username, level_num]
    return redirect("/login/success")


@app.route("/register/<string:random_str>", methods=['GET', 'POST'])
def register(random_str):
    """
    关于注册界面的直接路由控制函数
    :param random_str: 生成的随机token
    :return: 一个模板界面，通过字典给Jinjia传参
    """
    if session.get(USER_INFORMATION) is not None:
        return redirect("/")
    if request.method == 'GET':
        session[RANDOM_STR_TOKEN] = get_random_str(RAN_TOKEN_LEN)
        data = {
            "random_str": session.get(RANDOM_STR_TOKEN),
            "alert": "false"
        }
        if random_str == "warning":
            data["alert"] = "true"
            data.update({"msg": "就特么你小子是吧？(´ω｀★)"})
        elif random_str == "warning_":
            data["alert"] = "true"
            data.update({"msg": "亲，不要乱动数据包哦！(´ω｀★)"})
        elif random_str == "passwdwrong":
            data["alert"] = "true"
            data.update({"msg": "亲，确认密码输错了呢，再来一遍好不好？(´ω｀★)"})
        elif random_str == "namerepeat":
            data["alert"] = "true"
            data.update({"msg": "亲，眼光高远，但是这个用户名被人用过了呢，咱们换一个好不好呀！（☆ω☆*）"})
        elif random_str == "success":
            data.update({"msg": "注册成功了耶！那咱们快点去登录好不好吖（づ￣3￣）づ╭❤～", "target": "/login/1"})
            return render_template("html/tools/jump.html", data=data)
        return render_template('html/register.html', data=data)
    if session.get(RANDOM_STR_TOKEN) != random_str:
        # Situation1:The hacker changed the token_str.
        get_hacker(request)  # 抓进罐子里。key: HvRRjcgDbeGDEd4EuZeEaiJKC6P74p7LBg9Tv8rp6R
        session[RANDOM_STR_TOKEN] = None
        return redirect("/register/warning")
    username = request.form.get('username')
    password = request.form.get('password')
    corrpass = request.form.get('correctpwd')
    """回头可以在这边插入一下验证码相关的代码"""
    if password != corrpass:
        # Situation2:The confirm password is not right which is input by the user[ or hacker].
        session[RANDOM_STR_TOKEN] = None
        return redirect("/register/passwdwrong")
    if username is None or password is None or len(random_str) < RAN_TOKEN_LEN - 1:
        get_hacker(request)  # 抓进罐子里。key: HvRRjcgDbeGDEd4EuZeEaiJKC6P74p7LBg9Tv8rp6R
        session[RANDOM_STR_TOKEN] = None
        return redirect("/register/warning_")
    session[RANDOM_STR_TOKEN] = None
    register_status = register_sql(username=username, passwd_base=password, random=random_str)
    if register_status:
        # 注册成功
        return redirect("/register/success")
    else:
        # Situation3:The username has been used
        return redirect("/register/namerepeat")


@app.route("/log_out", methods=['GET'])
def log_out():
    if session.get(USER_INFORMATION) is None:
        # 未登录请先登录
        return redirect("/login/p")
    data = {
        "msg": session.get(USER_INFORMATION)[1] + "，您好！您已经成功退出登录！",
        "target": "/"
    }
    session[USER_INFORMATION] = None
    return render_template("html/tools/jump.html", data=data)


@app.errorhandler(400)
def handle_400_error(e):
    return render_template('error/400.html'), 400


@app.errorhandler(403)
def handle_403_error(e):
    return render_template('error/403.html'), 403


@app.errorhandler(404)
def handle_404_error(e):
    return render_template('error/404.html'), 404


@app.errorhandler(500)
def handle_500_error(e):
    return render_template('error/500.html'), 500


if __name__ == '__main__':
    app.run(
        host=RUNNING_HOSTS,
        port=RUNNING_PORT,
        debug=True,
    )
