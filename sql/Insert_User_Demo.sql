INSERT INTO `flask_scan`.`users` (id, username, level,passwd) VALUES (?, ?, ?, ?);
UPDATE `flask_scan`.`users` SET level=? WHERE id=?;
UPDATE `flask_scan`.`users` SET username=? WHERE id=?;
DELETE FROM `flask_scan`.`users` WHERE id=?;
/*
  下边的是python程序的写法（）
  -------------------
  创建超级用户admin
    id_value = str(int(time.time() * 10000))
    sql = "INSERT INTO `flask_scan`.`users` (id, username, level, passwd) VALUES (?, ?, ?, ?);"
    sql_run1(sql=sql, data=(id_value, 'admin', 1, hash_to_32(id_value + "123456")))
*//*
  下边的是创建普通用户的写法（一般的注册行为）
    id_value = str(int(time.time() * 10000))
    sql = "INSERT INTO `flask_scan`.`users` (id, username, passwd) VALUES (?, ?, ?);"
    sql_run1(sql=sql, data=(id_value, 'testuser', hash_to_32(id_value + "123456")))
*//*
  下边的是更新用户权限的写法
    sql = "UPDATE `flask_scan`.`users` SET level=? WHERE id=?;"
    sql_run1(sql=sql, data=(5[levelnum], '[idnum]'))
*//*
  更新用户名
    sql = "UPDATE `flask_scan`.`users` SET username=? WHERE id=?;"
    sql_run1(sql=sql, data=('[newname]', '[idnum]'))
*//*
  删除用户
    sql = "DELETE FROM `flask_scan`.`users` WHERE id=?;"
    sql_run1(sql=sql, data=('[idnum]'))
*/


