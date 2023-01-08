import hashlib
from hashlib import pbkdf2_hmac
import pymysql
import csv

class PassGen():
    def __init__(self):
        print("start")
        return


    def GetKey(self):
        print("请输入你的生成密钥")
        self.key = input()
        return

    def GetID(self):
        print("请输入你的账号")
        self.id = input()
        return

    def GetURL(self):
        print("请输入网页的网址")
        self.url = input()
        return

    def RegNewAccount(self):
        self.GetID()
        self.GetURL()
        self.GetKey()

        x = {'URL':self.url,'ID':self.id}
        with open('PassData.csv', 'a', newline='') as csvfile:
            fieldnames = ['URL', 'ID']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            #writer.writeheader()
            writer.writerow(x)
        return self.hash()


    def Login(self):
        self.GetID()
        self.GetURL()
        self.GetKey()
        return self.hash()


    def hash(self):
        iters = 100
        key = bytes(self.key, 'utf-8')
        id = bytes(self.id, 'utf-8')
        url = bytes(self.url, 'utf-8')
        dk1 = pbkdf2_hmac('sha256', key, id+url , iters).hex()
        self.hashpass = dk1
        print(dk1)
        return self.Hex2Password(self.hashpass)

    def Hex2Password(self,hex):
        RequestPosition = []
        #Big letter, Small letter, number, Symbol
        pt = 0
        while len(RequestPosition) < 4:
            var = hex[pt]
            Vaildflag = 1
            for position in RequestPosition:
                if var == position:
                    Vaildflag = 0
                    break
            if Vaildflag==1:RequestPosition.append(var)
            pt += 1

        Pswd = ''
        i = 0
        while len(Pswd) < 16:
            letter = hex[pt:pt+2]
            #print(letter)
            letter = int(letter,16)

            if i == RequestPosition[0]:
                q,l = divmod(letter,26)
                l += 97
                l = chr(l)

            elif i == RequestPosition[1]:
                q,l = divmod(letter,26)
                l += 65
                l = chr(l)

            elif i == RequestPosition[2]:
                q, l = divmod(letter, 10)
                l += 48
                l = chr(l)

            elif i == RequestPosition[3]:
                q,l = divmod(letter,15)
                l += 33
                l = chr(l)

            else:
                q,l = divmod(letter,93)
                l += 33
                l = chr(l)

            i += 1
            pt += 2
            Pswd += l
        #print(Pswd)
        print("密码生成完成，密码是：")
        return Pswd



obj = PassGen()
password = obj.RegNewAccount()
print(password)
