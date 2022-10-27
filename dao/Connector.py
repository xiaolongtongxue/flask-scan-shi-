"""
@File    ：Connector.py
@Author  ：TXK
@Date    ：2022/10/20 15:40 
"""
# -*- coding: UTF-8 -*-
from mysql import connector
from mysql.connector import Error

from bean.static import *


def get_connector():
    connection = connector.connect(
        host=MYSQL_HOST_IP,
        port=MYSQL_HOST_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWD,
        database=MYSQL_DB
    )
    cursor = connection.cursor(prepared=True)
    return [connection, cursor]


def sql_run1(sql: str, data: tuple):
    """

    :rtype: object
    """
    connection, cursor = get_connector()
    try:
        cursor.execute(sql, data)
        connection.commit()
        if connection.is_connected():
            cursor.close()
            connection.close()
        return INSERT_SUCCESSFULLY
    except Error as error:
        connection.rollback()
        print(f"Error occured : {error}")
        if connection.is_connected():
            cursor.close()
            connection.close()
        return INSERT_REPEAT_NAME


def sql_run2(sql: str, data: tuple):
    connection, cursor = get_connector()
    try:
        cursor.execute(sql, data)
        select_end = cursor.fetchall()
        connection.commit()
        if connection.is_connected():
            cursor.close()
            connection.close()
        return select_end
    except Error as error:
        connection.rollback()
        print(f"Error occured : {error}")
        if connection.is_connected():
            cursor.close()
            connection.close()
        return SELECT_ERROR
