from des import DES

x = DES(plainText="secretss",key="s3cr3tPy")
x.encrypt()
x.decrypt()

#y = DES(plainText="hello",key="secretss")
#y.encrypt()
#y.decrypt()
