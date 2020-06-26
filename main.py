import sys
import acs

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2 or len(sys.argv) > 4:
            print("ANTA BAKA?! Need only 3 parameters [size message_for_sign message_for_check_sign]!")
            sys.exit(-1)
        else:
            size = sys.argv[1]
            message_for_sign = sys.argv[2]
            message_for_check_sign = sys.argv[3]
            size = int(size)
            if size < 2:
                print("ANTA BAKA?! Number of signatories must be >= 2 !")
                sys.exit(-1)
            else:
                ring = acs.RingSign()
                ring.set_n(size)
                ring.set_l(1024)
                ring.set_q(1024)
                ring.set_keys()
                data_sign = ring.get_sign(message_for_sign)
                print("\n---------Begin signature---------\n")
                for item in data_sign:
                    print(f"{item}\n")
                print("\n----------End signature----------\n")
                print(f"Sign message is: {message_for_sign}\n")
                print(f"Message for check signature is: {message_for_check_sign}\n")
                if ring.verify_sign(data_sign, message_for_check_sign) == 1:
                    print("Signature is correct.\n")
                else:
                    print("Signature is incorrect.\n")
                sys.exit(1)
    except LookupError:
        print("Something was wrong ...\n")
        print("Verify the passed arguments.\n")
        sys.exit(0)
