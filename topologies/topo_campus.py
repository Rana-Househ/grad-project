from mininet.topo import Topo


class CampusTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        s4 = self.addSwitch("s4")

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s2, s4)

        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")
        h5 = self.addHost("h5")
        h6 = self.addHost("h6")

        self.addLink(h1, s3)
        self.addLink(h2, s3)
        self.addLink(h3, s3)

        self.addLink(h4, s4)
        self.addLink(h5, s4)
        self.addLink(h6, s4)


topos = {"campus": (lambda: CampusTopo())}
