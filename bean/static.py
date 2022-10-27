"""
以下数据的内容，存在意义，请勿随意更改
"""
RUNNING_PORT = 1888             # 系统默认运行端口
RUNNING_HOSTS = "0.0.0.0"       # 系统默认的可访问范围
MAX_ALLOW_SCAN = 16             # 子网掩码最多允许该值，默认为16
MIN_MASK_NUM = 32               # 子网掩码为32是tnd什么鬼
MYSQL_HOST_IP = "127.0.0.1"
MYSQL_HOST_PORT = 3306
MYSQL_USER = "root"
MYSQL_PASSWD = "123456"
MYSQL_DB = "flask_scan"
CODE_IMG_URL = "http://127.0.0.1:80/imgCode.php?code="     # 关于图形验证码的接口地址
RAN_TOKEN_LEN = 15              # random token的默认长度，并且该值不得小于15
LEVEL1 = "超级管理员"
LEVEL2 = ""
LEVEL3 = ""
LEVEL4 = ""
LEVEL5 = "游客"
SPLIT = "|*-[-*|"
"""
下边的字段是Session用到过的字段
"""
RANDOM_STR_TOKEN = 'random_str'     # 随机字符串token，一般在注册登录时会用到
LOGIN_FAIL_NUM = 'login_error_time'     # 登陆失败的次数
USER_INFORMATION = "user_information"   # 登录成功的用户的信息


"""
下边的字段是给Jinja传参用的data设计的
"""
FORM_HOSTS = "hosts"                # 表单中表示主机地址的name属性
FORM_PORTS = "ports"                # 表单中表示端口号或端口区间的name属性
FOR_NMAP = "model"                  # 表单中应单独表明nmap对端口的扫描模式
SCAN_ID = "scan_id"                 # 表单————scan_id
SCAN_HOSTS = "scan_hosts"           # 表单————scan_hosts
SCAN_ERRORCODE = "scan_errorcode"   # 表单————错误码
SCAN_BYWAY = "scan_byway"           # 表单————使用工具（1-3分别为scapy、nmap和socket）
SCAN_PORTS = "scan_ports"           # 表单————请求端口（支持模糊查询）
USER_NAME = "username"              # 表单————用户名
USER_NEW_PASSWD = "passwd"          # 表单————个人信息界面重置登录密码
USER_REP_PASSWD = "corrpasswd"      # 表单————重置密码时需要输入的确认密码


"""
以下数据为代表错误性质的数据，数据本身无意义
"""
NONE_VALUE = 107014             # 传了个寂寞
VALUE_NUK_LOWERSIZE = 107015    # 端口小于0
VALUE_NUM_OVERSIZE = 107016     # 端口号超过65535
VALUE_NUM_ERROR = 107017        # 传入端口格式为 a-b 或 a1,a2,a3 时，字符串出现格式错误
VALUE_SIZE_ERROR = 107018       # 传入端口格式为 a-b 时，出现 a>b 的情况
DNS_ERROR = 107019              # dns解析出现错误
IPV4_FORMAT_ERROR = 107020      # IPv4格式出错（比如说写了五个数或者单个数字大于等于255）
TARGET_TOO_MANY = 107021        # 网段中指定的 ip 过多，为防止恶意流量行为，从而设置
MIN_MASK_ERROR = 107022         # 子网掩码给了个32或者大于32······
IP_VALUE_ERROR = 107023         # 在ip网段列举其中全部ip地址的时候报错ValueError
INSERT_REPEAT_NAME = 107024     # 修改用户名或注册用户的时候用户名冲突
SELECT_ERROR = 107025           # select 语句查询出错（问题会打印在终端，请自行调取日志研判）


"""
以下数据为代表正确性质的数据，数据本身无意义
"""
INSERT_SUCCESSFULLY = 202011    # 数据插入/更新成功
USERNAME_NOT_EXIST = 202012     # 登陆时发现用户名不存在
PASSWD_ERROR = 202013           # 登陆时密码输入错误