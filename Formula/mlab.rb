class Mlab < Formula
  desc "CLI client for the mlab.sh threat intelligence and CVE APIs"
  homepage "https://github.com/mlab-sh/mlab-cli"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-darwin-arm64.tar.gz"
      sha256 "eb0a6f7e11f613ce4b7d0a366c26e6dd1d76852ee58d0d41edcb513d71e710e8"
    else
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-darwin-amd64.tar.gz"
      sha256 "339b63f4fecd0507ff909f54fa8fe5f7203c4c477d301ead3cf4ed5937505a4e"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-linux-amd64.tar.gz"
      sha256 "8adca84a18ac6987b5741fe3729ee02c1193582c8ea54e0680932e2d612168f2"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-linux-arm64.tar.gz"
      sha256 "ca3df52e3adde04c5212a7acceb9fcaa2d1b4618de59da0fe3a9eb3c33b4d7f4"
    end
  end

  def install
    bin.install "mlab"
  end

  test do
    assert_match "mlab", shell_output("#{bin}/mlab --version")
  end
end
