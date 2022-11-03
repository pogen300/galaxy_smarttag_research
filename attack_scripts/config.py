def init():
    global LOCAL_NAME
    global payloadstr
    global payload
    global mainloop
    global tag_nonce
    global enc_nonce
    global phone_nonce
    global myclass
    global plain
    global hashed_sn
    global sn
    global nonregistered_data
    global privacy_seed
    global privacy_iv
    global mastersecret
    global addr
    global is_silent_pairing
 
    addr = '00'
    sn = '00'
    hashed_sn = '00'
    nonregistered_data = '00'
    privacy_seed = None
    privacy_iv = None
    mastersecret = None
    LOCAL_NAME = 'Smart Tag'
    payloadstr = 'Testing silent pairing'
    payload = payloadstr.encode('ascii')
    mainloop = None
    tag_nonce = None
    enc_nonce = None
    phone_nonce = None
    myclass = None
    plain = b'smartthings'
    is_silent_pairing = False