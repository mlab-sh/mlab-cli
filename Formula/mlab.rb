class Mlab < Formula
  desc "CLI client for the mlab.sh threat intelligence and CVE APIs"
  homepage "https://github.com/mlab-sh/mlab-cli"
  version "1.1.0"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "d4d0fd710893a9f4d5c5d828edf135edd9fd3db182324417fe2fe869fd01f621"
    else
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "d396e485f951acda0543fb24a425a3f45250eb31715d5f99748ab8b237072ff7"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4320265f29f09d22b9aecbc0e9348b25530bab0e9a182986ba2564beb06cb03c"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "deac49cf2e1d3aa261739fadcd292cd00489faaa0d6ecc253d3a67f94f785edb"
    end
  end

  def install
    bin.install "mlab"
  end

  test do
    assert_match "mlab", shell_output("#{bin}/mlab --version")
  end
end
