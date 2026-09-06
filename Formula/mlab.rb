class Mlab < Formula
  desc "CLI client for the mlab.sh threat intelligence and CVE APIs"
  homepage "https://github.com/mlab-sh/mlab-cli"
  version "1.0.4"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "3ecddc07fc465a068163c32269ea1e29ec7cec7e587eff5102778a08cbd52d2a"
    else
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "60353fddd12862478028a9b1659cb3f1c0d033baadcf08b9102241f0f493ad0b"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "097a0c6d735076eb7f0dcd1cc949fb3fb8c25f68446e83fc6cdf2ef056af766f"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b29b154a1d6a2689ce572eace81188b81d5c874fda19c0f9df0b4b44f2685370"
    end
  end

  def install
    bin.install "mlab"
  end

  test do
    assert_match "mlab", shell_output("#{bin}/mlab --version")
  end
end
