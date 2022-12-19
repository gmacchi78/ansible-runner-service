import os
import sys
import unittest
import logging
import uuid
from runner_service.utils import SecureContext, InvalidUserException


class TestSecureContext(unittest.TestCase):

    base_dir = "/tmp/ars-test"
    database = f"{base_dir}/users.db"

    def setUp(self) -> None:
        try:
            os.mkdir(self.base_dir)
        except OSError as error:
            pass

        if os.path.exists(self.database):
            os.remove(self.database)
        return super().setUp()

    def test_database_creation(self):
        self.assertFalse(os.path.exists(self.database))
        SecureContext.get_or_create(self.base_dir)
        self.assertTrue(os.path.exists(self.database))

    def test_get_user_ok(self):
        SecureContext._create_database(
            database=self.database, admin_passwd='password')
        sc = SecureContext.get_or_create(self.base_dir)
        user = sc.get_user(user_name='admin', passwd='password')
        self.assertFalse(user is None)
        self.assertTrue(user.expired)

    def test_get_user_fail(self):
        SecureContext._create_database(
            database=self.database, admin_passwd='password')
        sc = SecureContext.get_or_create(self.base_dir)
        
        self.assertRaises(InvalidUserException,
                          sc.get_user, 'admi', 'password')

        self.assertRaises(InvalidUserException, sc.get_user, 'admin', '1')


    def test_change_password_fail(self):
        SecureContext._create_database(
            database=self.database, admin_passwd='password')
        sc = SecureContext.get_or_create(self.base_dir)
        self.assertRaises(InvalidUserException,
                          sc.update_password, 'admin', 'pas', 'abc')


    def test_change_password_fail(self):
        SecureContext._create_database(
            database=self.database, admin_passwd='password')
        sc = SecureContext.get_or_create(self.base_dir)
        user = sc.update_password(user_name='admin',old_passwd='password', new_passwd='abc')
        self.assertFalse(user.expired)