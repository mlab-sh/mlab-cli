class Mlab < Formula
  desc "CLI client for the mlab.sh threat intelligence and CVE APIs"
  homepage "https://github.com/mlab-sh/mlab-cli"
  version "1.0.3"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "f9fc1693b620269286158478d08282b0101f79082f55f45bd7b399e50f53ae26"
    else
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "f704f0cc5344f026457a7f043a3827bd1b0a5bd1cb138dbce80debbd143fc3c2"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "47da7bc9fed4aa1ebc9fabc310a1e47bd0ce80be023e0a7d64cf1c1949ade38d"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "f3662d0896c311a1e3c22aede141635320471a2f10eb72c0872ea17bc94d6154"
    end
  end

  def install
    bin.install "mlab"
  end

  test do
    assert_match "mlab", shell_output("#{bin}/mlab --version")
  end
end
