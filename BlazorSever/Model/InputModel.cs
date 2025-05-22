using System.ComponentModel.DataAnnotations;

namespace BlazorSever.Model
{
    public class InputModel
    {
        [Required]
        public string? Username { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string? Password { get; set; }
    }
}
