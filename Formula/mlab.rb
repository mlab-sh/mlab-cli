class Mlab < Formula
  desc "CLI client for the mlab.sh threat intelligence and CVE APIs"
  homepage "https://github.com/mlab-sh/mlab-cli"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-darwin-arm64.tar.gz"
      sha256 "b0ec84c5d59963a51e2c01797cf761e502522360d29bdd24ffa7d685f306272e"
    else
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-darwin-amd64.tar.gz"
      sha256 "d5997cbbc5147f51eca2d24ecae3829ce546d4df479ad3448535eac5130eea50"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-linux-amd64.tar.gz"
      sha256 "3a70ec6d815ae938ff58abf8769fcfe57c257e76845621260db143fec3fb4aeb"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-cli/releases/download/v#{version}/mlab-linux-arm64.tar.gz"
      sha256 "8d4fba879457ff875340e2af9b68528bee539591b066873d26361f3c940d0806"
    end
  end

  def install
    bin.install "mlab"
  end

  test do
    assert_match "mlab", shell_output("#{bin}/mlab --version")
  end
end
