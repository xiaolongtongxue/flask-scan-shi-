SELECT * FROM `flask_scan`.`users`;
SELECT * FROM `flask_scan`.`users` WHERE id=?;
SELECT level FROM `flask_scan`.`users` WHERE id=?;
SELECT username FROM `flask_scan`.`users` WHERE id=?;
/*
  下边的是python程序的写法（）
  -------------------
  查询全部用户信息
    sql = "SELECT * from `flask_scan`.`users`"
    a = sql_run2(sql=sql, data=())
    print(a)
    # [('16662539436467', 'admin', 1), ('16662555637307', 'testuser', 5)]
*//*
  带参数的查询，后边的逗号很重要！！！
  ------------------
  根据id查询全部信息
    sql = "SELECT * from `flask_scan`.`users` WHERE id=?;"
    a = sql_run2(sql=sql, data=('16662539436467',))
    print(a)
  # [('16662539436467', 'admin', 1)]
*//*
  根据id查看用户等级权限
    sql = "SELECT level FROM `flask_scan`.`users` WHERE id=?"
    a = sql_run2(sql=sql, data=('16662539436467',))
    print(a)
    # [(1,)]
*//*
  根据id查询用户名
    sql = "SELECT username FROM `flask_scan`.`users` WHERE id=?;"
    a = sql_run2(sql=sql, data=('16662539436467',))
    print(a)
    # [('admin',)]
*/
