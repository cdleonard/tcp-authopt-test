"""Python translation of https://datatracker.ietf.org/doc/draft-touch-sne/"""


def distance(x, y):
    if x < y:
        return y - x
    else:
        return x - y


class SequenceNumberExtender:
    rcv_sne: int = 0
    rcv_sne_flag: bool = True
    rcv_prev_seq: int = 0

    def calc(self, seq):
        """Update SNE info

        Returns SNE for packet with a certain SEQ and updates internal state"""
        # use current SNE to start
        result = self.rcv_sne

        # both in same SNE range?
        if distance(seq, self.rcv_prev_seq) < 0x80000000:
            # jumps fwd over N/2?
            if seq >= 0x80000000 and self.rcv_prev_seq < 0x80000000:
                self.rcv_sne_flag = False
            # move prev forward if needed
            self.rcv_prev_seq = max(seq, self.rcv_prev_seq)
        # both in diff SNE ranges?
        else:
            # jumps forward over zero?
            if seq < 0x80000000:
                # update prev
                self.rcv_prev_seq = seq
                # first jump over zero? (wrap)
                if self.rcv_sne_flag == 0:
                    # set flag so we increment once
                    self.rcv_sne_flag = 1
                    # increment window
                    self.rcv_sne = self.rcv_sne + 1
                    # use updated SNE value
                    result = self.rcv_sne
            # jump backward over zero?
            else:
                # use pre-rollover SNE value
                result = self.rcv_sne - 1

        return result
