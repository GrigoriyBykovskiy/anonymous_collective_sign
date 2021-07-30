import sys
import os
import acs

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2 or len(sys.argv) > 4:
            print("ANTA BAKA?! Need only 3 parameters:\n"
                  "1) for sign (-sign) [size message_for_sign]!\n"
                  "2) for check (-check) [message_for_check signature_filename]!\n")
            sys.exit(-1)
        else:
            if sys.argv[1] == "-sign":
                size = sys.argv[2]
                message_for_sign = sys.argv[3]
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
                    ring.get_sign(message_for_sign)
                    print("\n---------Begin signature---------\n")
                    for item in ring.data_signatures:
                        print(f"{item}\n")
                    print("\n----------End signature----------\n")
                    filename = ring.export_data_signatures_to_CSV()
                    print(f"Signature save to: {os.path.abspath(__file__)} {filename}")
                sys.exit(1)
            if sys.argv[1] == "-check":
                message_for_check_sign = sys.argv[2]
                filename = sys.argv[3]
                ring = acs.RingSign()
                ring.import_data_signatures_from_CSV(filename)
                print(f"Message for check signature is: {message_for_check_sign}\n")
                print("\n---------Begin signature---------\n")
                for item in ring.data_signatures:
                    print(f"{item}\n")
                print("\n----------End signature----------\n")
                if ring.verify_sign(ring.data_signatures, message_for_check_sign) == 1:
                    print("Signature is correct.\n")
                else:
                    print("Signature is incorrect.\n")
                sys.exit(1)
            else:
                print("ANTA BAKA?! Wrong key passed!\n")
                sys.exit(-1)
    except LookupError:
        print("Something was wrong ...\n")
        print("Verify the passed arguments.\n")
        sys.exit(0)
